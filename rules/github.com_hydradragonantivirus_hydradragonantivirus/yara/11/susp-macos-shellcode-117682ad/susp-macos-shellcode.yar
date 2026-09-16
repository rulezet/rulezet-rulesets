rule susp_macos_shellcode {
  meta:
    description = "Identify macOS shellcode from @evilbit."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.15"
    reference   = "https://github.com/theevilbit/shellcode/tree/master/osx/x64"
    DaysofYARA  = "74/100"

  strings:
    $binsh = {
      48 31 f6                             56                                   48 bf 2f 2f 62 69 6e 2f 73 68        57                                   48 89 e7                             48 31 d2                             48 31 c0                             b0 02                                48 c1 c8 28                          b0 3b                                0f 05                              }

    $bindsc = {
      48 31 ff                             40 b7 02                             48 31 f6                             40 b6 01                             48 31 d2                             48 31 c0                             b0 02                                48 c1 c8 28                          b0 61                                49 89 c4                             0f 05                                49 89 c1                             48 89 c7                             48 31 f6                             56                                   be 01 02 11 5c                       83 ee 01                             56                                   48 89 e6                             b2 10                                41 80 c4 07                          4c 89 e0                             0f 05                                48 31 f6                             48 ff c6                             41 80 c4 02                          4c 89 e0                             0f 05                                48 31 f6                             41 80 ec 4c                          4c 89 e0                             0f 05                                48 89 c7                             48 31 f6                             41 80 c4 3c                          4c 89 e0                             0f 05                                48 ff c6                             4c 89 e0                             0f 05                                48 31 f6                             56                                   48 bf 2f 2f 62 69 6e 2f 73 68        57                                   48 89 e7                             48 31 d2                             41 80 ec 1f                          4c 89 e0                             0f 05                              }

  condition:
    any of them
}