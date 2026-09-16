rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9ea913782e3bbe537d44a544b7c786a18913cc4ed3f2a3231b9868ac1541233"

  strings:
    $s1 = "<Module>{040E0824-4B07-4E4D-8621-4C8A7ADE447E}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}