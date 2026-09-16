rule Virus_Hijack_Trojan_Agent_DQQO_159_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_159_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d0b256f9581a1ee07c3f1de6bf6383a17a0a69cf773ae34fcc669f5f9862fc6"

  strings:
    $x1 = "Bm@54cwoBm@j4gVQ4cwoBe@84gPZhKngwCyRB0Og3nI84cyREM8gB0@Qge@a@CyRBgPRP0iFBgVRge@R21woBm@jgeJtg6Ia@CyRBgPRoNvhBZA51gVvAfqgjv0OyLZg" ascii
    $s2 = "JAtlQ9!3XGVV2Gig uoEFwOgABQ3XxwgAs6g!hu!griT bWOlGgx54qPaOgOgEtiPhZYyO7OgEFygFrVo@z5vGP!4aBn Hx8XgPWsILglneHGhZg55RNPIjWV7kg2fL2" ascii
    $s3 = "VmA4vyngXWgadODfvi6g7K1Ygg41iArO9uP@gcRgGgPlg6X@Ezba!L6ngHecgotT2zzp@ugh PL8tBAINOgLiCxgtNIORMLgqJVYPhy7XuigLHY9gPN9DR@ywOP5i0J0" ascii
    $s4 = "gen5CNgFkGVBWzYx5OPQgcblTb0 PQ9!gVxAgKRyLlp5vuPOO IzyMJT@GVPZizgMW0!8lZgN!pXJUsm0uxg5tabggFiD!siRuP@fgxp1OH3gFZHeOL5nUI3gEwegZWc" ascii
    $s5 = "WWc4w5nhgtfego!TvaW ROPy!yikvMrI8OPAafOges5mWWFg0wdMfIfeddxgvaW groy!yikvGVNsBoAagPzgPa55lC 0wdMgP!JgZ4hm!p1qOH@khk!eoYNsOH2q4Og" ascii
    $s6 = "fRet;S%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}