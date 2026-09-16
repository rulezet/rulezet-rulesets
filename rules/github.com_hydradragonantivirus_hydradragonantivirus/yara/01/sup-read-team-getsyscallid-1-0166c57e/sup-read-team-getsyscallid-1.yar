rule SUP_READ_TEAM_GETSYSCALLID_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule detecting opcodes for an observed GetSyscallId function in red team tools."
    reference   = "https://github.com/nettitude/Tartarus-TpAllocInject/blob/main/TpAllocInjection/SyscallsGen.cpp#L21-L92"
    DaysofYARA  = "3/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-03"
    version     = "1.0"
    hash1       = "2dc2c00880d2115b0f9cb7dc04e36fc4b93e6f0d6557b6d88e41fab0b577875b"
    hash2       = "d43442ea05eefbf73d35109eea7ace3e26713d26dc1d945bdc260480c2a0b718"
    hash3       = "ed7731e01311ab07c893293cd3e67c64d45aa8b33ac7fe344e3499417924e7e7"

  strings:
    $ = {
      0f b6 02           3c 4c              75 ??              ?? ?? 01 8b        75 ??              ?? ?? 02 d1        75 ??              ?? ?? 03 b8        75 ??              44 38 42 06        75 ??              44 38 42 07        75 ??            }
    $ = {
      45 8b c1              41 c1 e0 05           4c 03 c2              41 80 38 4c           75 ??                 41 80 78 01 8b        75 ??                 41 80 78 02 d1        75 ??                 41 80 78 03 b8        75 ??                 41 80 78 06 ??        75 ??                 41 80 78 07 ??        74 ??               }
    $ = {
      41 80 38 4c              75 ??                    41 80 78 01 8b           75 ??                    41 80 78 02 d1           75 ??                    41 80 78 03 b8           75 ??                    41 80 78 06 ??           75 ??                    41 80 78 07 ??           0f 84 ?? ?? ?? ??      }
    $ = {
      41 80 38 4c           75 ??                 41 80 78 01 8b        75 ??                 41 80 78 02 d1        75 ??                 41 80 78 03 b8        75 ??                 41 80 78 06 ??        75 ??                 41 80 78 07 ??        74 ??               }
    $ = {
      41 80 38 4c           75 ??                 41 80 78 01 8b        75 ??                 41 80 78 02 d1        75 ??                 41 80 78 03 b8        75 ??                 41 80 78 06 ??        75 ??                 41 80 78 07 ??        74 ??               }

  condition:
    uint16(0) == 0x5A4D
    and (uint32(uint32(0x3C)) == 0x00004550)
    and all of them
    and filesize < 10MB
}