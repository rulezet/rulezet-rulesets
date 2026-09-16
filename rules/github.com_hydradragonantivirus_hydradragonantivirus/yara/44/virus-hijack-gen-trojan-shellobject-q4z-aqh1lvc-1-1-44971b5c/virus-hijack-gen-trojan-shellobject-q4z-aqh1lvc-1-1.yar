rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b203920d8701c85c3c8da0eac1eeeda217cdb5d4c5d6775d67219956e0295cf"

  strings:
    $s1 = "\"tEEl&bM,S" fullword ascii
    $s2 = "?skaT}" fullword ascii
    $s3 = "8{rESp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}