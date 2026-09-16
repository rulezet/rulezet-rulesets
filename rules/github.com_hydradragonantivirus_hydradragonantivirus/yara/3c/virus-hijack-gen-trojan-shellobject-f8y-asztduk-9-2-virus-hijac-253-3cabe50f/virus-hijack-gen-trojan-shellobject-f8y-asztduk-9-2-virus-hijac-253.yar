rule _Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_9_2_Virus_Hijac_253 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8abf3c3e2ecdf986aa569cab07055dd825520f52bceed0d17c502661c108cbf2"
    hash2       = "8bb24d7147c7f8b0ceb987045095bf8e35e1876cb028a6fe705e72802b3ab17c"
    hash3       = "c772e695436eec26a176fc65b88f0f8a674bd64cdc6f577bcf3a95b987d48204"

  strings:
    $s1 = "Windows Media Center MXF Loader" fullword wide
    $s2 = "Windows Media Center MFX Loader" fullword ascii
    $s3 = "Windows Media Center MXF Loader" fullword ascii
    $s4 = "Exception when opening {0}" fullword wide
    $s5 = "Exception encountered" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}