import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_29_2_Virus_Hija_317 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_29_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.suZ@amBwvTb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c5ca4d7111081820e7dded370d91e07f62d145fe9e8c5b39b45e9957ff0aff1"
    hash2       = "2f2a15123167fe5a66aa0e6b7b64f446103711dc24554c352eebc64717e76775"
    hash3       = "d2b685a8458cf4086cac5842366a984f4bb7757560b416778c09d099410a9852"
    hash4       = "89824e8cb86a68f37cb5ff17901a69ebc18e6e762d6513e589ea94b854057a45"
    hash5       = "4526b610d55d0a767e8391617838ec9a25c20bc8f5dd3c6bcbf1b7bd43fdc818"

  strings:
    $s1  = "{----- Transcript of {the ||}session follows -----" fullword ascii
    $s2  = "{We suspect that|Probably,|Most likely|Obviously,} your computer {had been|was} {compromised|infected{ by a recent v{iru}s|}} an" ascii
    $s3  = "554 <$t>... Service unavailable|550 5.1.2 <$t>... Host unknown (Name server: host not found)|554 {5.0.0 |}Service unavailable; [" ascii
    $s4  = "$i] blocked using {relays.osirusoft.com|bl.spamcop.net}{, reason: Blocked|}" fullword ascii
    $s5  = "{We have {detected|found|received reports} that y|Y}our {e{-|}mail |}account {has been|was} used to send a {large|huge} amount o" ascii
    $s6  = "{We suspect that|Probably,|Most likely|Obviously,} your computer {had been|was} {compromised|infected{ by a recent v{iru}s|}} an" ascii
    $s7  = "|}{<<< 400-aturner; -SYSTEM-F-EXDISKQUOTA, disk quota exceeded" fullword ascii
    $s8  = "|}{<<< 400-aturner; -RMS-E-CRE, ACP file create failed" fullword ascii
    $s9  = "{We have {detected|found|received reports} that y|Y}our {e{-|}mail |}account {has been|was} used to send a {large|huge} amount o" ascii
    $s10 = "Session aborted{, reason: lost connection|}|>>> RCPT To:<$t>" fullword ascii
    $s11 = "Dear user {$t|of $T},{ {{M|m}ail {system|server} administrator|administration} of $T would like to {inform you{ that{:|,}|}|let " ascii
    $s12 = "d now {run|contain}s a {trojan{ed|}|hidden} proxy server." fullword ascii
    $s13 = "Dear user {$t|of $T},{ {{M|m}ail {system|server} administrator|administration} of $T would like to {inform you{ that{:|,}|}|let " ascii
    $s14 = "{{{Mail s|S}erver}|Host} $i is not responding." fullword ascii
    $s15 = "Please reply to postmaster@{$F|$T}" fullword ascii
    $s16 = "zincite" fullword ascii
    $s17 = "{Please|We recommend {that you|you to}} follow {our |the |}instruction{s|} {in the {attachment|attached {text |}file} |}in order" ascii
    $s18 = "{Please|We recommend {that you|you to}} follow {our |the |}instruction{s|} {in the {attachment|attached {text |}file} |}in order" ascii
    $s19 = "{<<< 400-aturner; %MAIL-E-OPENOUT, error opening !AS as output" fullword ascii
    $s20 = " to keep your computer safe." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "7ee89a85ea0ffd700fd28e6cfa3d968f" and (8 of them)
    ) or (all of them)
}