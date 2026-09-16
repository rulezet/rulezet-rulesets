rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_2_Virus_Hijack_267 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aOU94xe_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aC!4gaf_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGN6KMb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGN6KMb_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iuZ@aiy413e_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.jzZ@aCEmdoo_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.LzZ@aWELKOd_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_22_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aKTibuk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash2       = "ec1044d880da5cfd0f6b1bfb8cd6a5311788ea349e14ab614f901273f4f19e26"
    hash3       = "07639822096ce7ab6cdc94ca84a2b32c4eb49c1c64341bfcbb600efeda6cec65"
    hash4       = "6f188ea2f39423650ee171ea4f42df70a4f88b9bca1c3774903fbc60049711e3"
    hash5       = "bc353c85b241d1eadde000f6db8b02d66c49ada71d2b320c915872bfa1ce1fe2"
    hash6       = "ac681da8d24a42342dda98a6adaf471896cb6832bb019259a76d127e917c8f30"
    hash7       = "bb9e029a806bd23a94c78e2753dbd33f6772e833b2da9480fa91642aa52dd368"
    hash8       = "745a3679627500fedf225a0bfd1592163d8a2da07f74398c0f38a18d5cc67522"
    hash9       = "c1ac2626c0f2e35b2b7a55db44b37b0d4653890090f6ee47746f743666d4b40b"
    hash10      = "f9bbe61f7b00b61c0d61fef200c54c73c8337d9bf093c6acc4d4932e28089dbb"
    hash11      = "4b456ca90bcb59a6fe6c7073a0e73c212bebfa5bb579618749a4e80fd584f61b"
    hash12      = "365fc0d821440b0e22b6c196db0612be11328bde72c7b0dc7b96005c77d09d4f"
    hash13      = "07b5c73e648c47e533c671c01b6b25727b3323496c9faf9b521844a9f0e56561"
    hash14      = "f0034ed038a083f038d51b7f29e883391cdc631ceab98ffb3cb94b48cff79719"
    hash15      = "9e9fe24cd10be47106b354f49af78a2a64ada1496ef7ec2f382c998dd356f9a7"
    hash16      = "2708109d58cfd1465c91565636e937ec09edb2209239a49f462240c1ccc37800"
    hash17      = "f9110796197308daa263e166d4b838ddf00a052091f22824f1e9b165ea38eeb5"
    hash18      = "fb159bfd435d3e6379a2a784ee8898b472b9e1b84f32bb5845e90b9286444637"
    hash19      = "c69bf4fdbb8372d02e038c6254627c176c9151ec738396bf45780822a3ec027a"
    hash20      = "ff451c9e09eef51e5fa6a320cd22fd5e78661fc7d570b1b081006e82c3734558"

  strings:
    $s1  = "<RichText id=\"atom(DialogContent)\" layoutpos=\"top\" contentalign=\"wrapleft | noprefix\" accessible=\"true\" accrole=\"static" ascii
    $s2  = "<RichText id=\"atom(DialogContent)\" layoutpos=\"top\" contentalign=\"wrapleft | noprefix\" accessible=\"true\" accrole=\"static" ascii
    $s3  = "<element resid=\"DialogRoot\" layout=\"borderlayout()\" accessible=\"true\" accrole=\"pane\">" fullword ascii
    $s4  = "r % 1 geplante Windows - Update ist bereit.Wenn Sie jetzt keine Zeit haben, versuchen wir es in einer Stunde noch einmal." fullword wide
    $s5  = "Head asjad on kohe tulekul" fullword wide
    $s6  = "re not ready, we" fullword wide
    $s7  = "re ready for the Windows update scheduled at %1. If you" fullword wide
    $s8  = "ts pour la mise " fullword wide
    $s9  = "r redo nu " fullword wide
    $s10 = "inde tekrar kontrol edece" fullword wide
    $s11 = "re all set for the Windows update scheduled at %1. If you" fullword wide
    $s12 = "ll check back again in an hour." fullword wide
    $s13 = "Countdown to goodness" fullword wide
    $s14 = "Vent en time" fullword wide
    $s15 = "ver vi igen om en time." fullword wide
    $s16 = "ll check with you again in an hour." fullword wide
    $s17 = "Esperar una hora" fullword wide
    $s18 = "Lo tenemos todo listo para la actualizaci" fullword wide
    $s19 = "s listo, te lo volveremos a preguntar en una hora." fullword wide
    $s20 = "Tenemos todo listo para la actualizaci" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}