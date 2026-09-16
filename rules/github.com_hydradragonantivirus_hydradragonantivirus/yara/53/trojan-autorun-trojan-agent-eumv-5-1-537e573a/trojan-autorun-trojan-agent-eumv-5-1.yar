rule Trojan_Autorun_Trojan_Agent_EUMV_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.EUMV_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dd79d2a18205b50b3efb8058faaf49745a29eff2ee66c3dc274dd30f0aca1e8"

  strings:
    $s1 = "TO RESOLVE A DISPUTE WITH THE MA NUFA CTURER OR INSTALLER, OR`" fullword ascii
    $s2 = "@syour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}