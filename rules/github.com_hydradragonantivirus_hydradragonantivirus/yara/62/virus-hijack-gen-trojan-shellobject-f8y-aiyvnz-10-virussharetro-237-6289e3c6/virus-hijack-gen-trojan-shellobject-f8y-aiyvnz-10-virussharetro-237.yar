rule _Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aiYvnz_10_VirusShareTro_237 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_10.vir, VirusShareTrojanClick331128_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4ee7fbba33edc2cc6988fcacfd32e21fab0c423649695616f2433babc63ed2f"
    hash2       = "0dabf22c56c996c3099a60988f2e341d67515be0c8230ba39b14d2ccd65019ea"

  strings:
    $s1  = "Using primary token from elevated process" fullword wide
    $s2  = "Using linked token from not elevated process" fullword wide
    $s3  = "GetTokenFromAdobeArmProcess disabled for testing" fullword wide
    $s4  = "GetTokenFromAdobeArmProcess finished without token" fullword wide
    $s5  = "GetTokenFromValidUserProcess finished without token" fullword wide
    $s6  = "Service workflow failed" fullword wide
    $s7  = "null token" fullword wide
    $s8  = "Linked token created" fullword wide
    $s9  = "User Token with privileges found" fullword wide
    $s10 = "User did not match, skipping" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}