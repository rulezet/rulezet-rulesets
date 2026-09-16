rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_149 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_149.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77490fea3873b21a0b082f486406a1e1f35dfd069fff30751cbe1c03f3fc3538"

  strings:
    $s1 = ")Resource instance not specified, did you call CommonLibraryDllProcessAttach?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}