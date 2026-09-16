rule Virus_Hijack_GenPack_Backdoor_Hangup_B_326 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_326.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28d1e8cfc2ba68b2cb33a3d0cfa05ba330d726e805c9128cdb9c4aa96320e04f"

  strings:
    $s1 = "0create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}