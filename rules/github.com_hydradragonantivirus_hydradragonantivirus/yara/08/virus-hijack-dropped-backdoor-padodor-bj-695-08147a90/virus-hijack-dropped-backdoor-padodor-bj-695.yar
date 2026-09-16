rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_695 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_695.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e52197ca7b61f9a3ca5c2cf69bc75a7c450cb870f987b7d86704287b8f12b688"

  strings:
    $s1 = "]are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}