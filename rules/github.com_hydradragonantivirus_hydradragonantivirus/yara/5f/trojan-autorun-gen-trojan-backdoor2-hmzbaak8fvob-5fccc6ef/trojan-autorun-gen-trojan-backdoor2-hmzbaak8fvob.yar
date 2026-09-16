rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaaK8fvob {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaaK8fvob.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a85cdfe2b9ad9dd1751929c117551ca31ef7bc42c8850ce8eafd2cd529d0e5b1"

  strings:
    $s1 = "lSaveGCConsentInfo::User consent saved successfully = " fullword wide
    $s2 = "CustomActionInfo: INFO: [IsAppRunningInReducedMode] : sEntitlementStatus not set to EXPIRED, not running in RM" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}