rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_19_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_19_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32eba121b45fa4d76fcfc49a01b9157ab680bbed33ab9783d5c81dae6935a817"

  strings:
    $s1 = "?loadPlugin@SAMPFUNCS@@QAEXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z" fullword ascii
    $s2 = "Ashot Samp | 05 region | Kavkaz RP | Prodazha baranov" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}