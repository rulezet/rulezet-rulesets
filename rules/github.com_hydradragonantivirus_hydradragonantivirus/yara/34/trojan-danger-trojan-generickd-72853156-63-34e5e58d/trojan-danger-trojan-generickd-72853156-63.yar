rule Trojan_Danger_Trojan_GenericKD_72853156_63 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_63.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb3cbb3be5a81e393b8cffd73915771f28aebd8966993eb60299dd6ee423d1ca"

  strings:
    $s1 = "Check For Updates.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}