rule APT_fnv1a_plus_extra_XOR_in_x64_experimental {
  meta:
    description = "This rule detects the specific x64 implementation of fnv1a like used in the SUNBURST backdoor (standard fnv1a + one final XOR before RET), rewritten in c. (fnv64a_offset and fnv64a_prime are standard constants in the fnv1a hashing algorithm.)"
    reference   = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
    author      = "Arnim Rupp"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    date        = "2020-12-22"

  strings:
    $fnv64a_offset                      = { 25 23 22 84 e4 9c f2 cb }
            $fnv64a_prime_plus_gap_plus_xor_ret = { B3 01 00 00 00 01 [4-44] (31 | 33) [0-1] C3 (90 | 66 90 | 0F 1F 00 | 0F 1F 40 00 | 0F 1F 44 00 00 | 66 0F 1F 44 00 00 | 0F 1F 80 00 00 00 00 | 0F 1F 84 00 00 00 00 00 | 66 0F 1F 84 00 00 00 00 00) }

  condition:
        (uint16(0) == 0x5a4d or uint32be(0) == 0x7f454c46) and all of them
}