rule _Trojan_Sysbot_Win32_Sality_OG_Virus_Hijack_Gen_Trojan_ShellObje_495 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Win32.Sality.OG.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_10.vir, VirusShareTrojanClick331128_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "120f7acdbf3d59840d53f9b96331cecb39380ce4d32e2def2b8d29a87f814120"
    hash2       = "e4ee7fbba33edc2cc6988fcacfd32e21fab0c423649695616f2433babc63ed2f"
    hash3       = "0dabf22c56c996c3099a60988f2e341d67515be0c8230ba39b14d2ccd65019ea"

  strings:
    $s1 = "User from command line: " fullword wide
    $s2 = "Couldn't get the full ARM path" fullword wide
    $s3 = "Adobe ARM launcher started." fullword wide
    $s4 = "Launched to fix ownership" fullword wide
    $s5 = "Setting for launch from self-update" fullword wide
    $s6 = "ARM path: " fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}