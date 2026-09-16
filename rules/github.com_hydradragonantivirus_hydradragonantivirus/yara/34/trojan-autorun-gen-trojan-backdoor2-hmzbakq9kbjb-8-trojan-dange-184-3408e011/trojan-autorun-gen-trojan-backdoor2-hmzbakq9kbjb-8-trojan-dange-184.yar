rule _Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_8_Trojan_Dange_184 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_8.vir, Trojan.Danger_Trojan.GenericKD.67166905_437.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Danger_Gen.Trojan.ShellObject.f8W@aKoUq3b_5.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_13_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_163_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_189_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_201_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_241_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_259_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9828657621996bbeea1519edbc2d237807230291dabde50e73596d757565f994"
    hash2       = "689031f531b7d9ad83bae78ff0e402b8426162866f17ac680945797b1cfc6eed"
    hash3       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash4       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash5       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash6       = "e27d09fa30ac00e7863ae318a349de4110626fdfa9423b7fad69666d9585def0"
    hash7       = "95cdc6e1c462932b44d96c9ee434cc3de4e20acab7717abaf524c17315d585b8"
    hash8       = "3ac7f62f4ef222c43700d5ec2ba2b4cd37515edba3ef6b7c1ee7459419d5c702"
    hash9       = "44fedf6976cda29deef5c664184651784a3b1c9a4c6b07f59acd093eebadee7d"
    hash10      = "d48ef14c519404cf9329c4b269ef6966219667ab04e71cdecb5929c364d58c84"
    hash11      = "b45e19ca33e2a0b101541844bf1852c429c2e5a6b6a40129c721ea9b75629c90"
    hash12      = "fd3bef3a8bd095762b6f798515a7c714f605fa8a1619a40f0b3016a31c5bf00c"
    hash13      = "aed769307e38ba23233c9e5bd676f009bcc5871cc4f6dd1447e662ca109bd72d"
    hash14      = "67ef84dfef19e55a6c230a10a42f614fe523d062ea7f152c7a31b30b4f4a31ff"

  strings:
    $s1  = "Failed to extract VCRT64 command line from ini. Hence using default command line %s." fullword wide
    $s2  = "hrend der Installation ist ein Fehler bei Acrobat DC aufgetreten. Deinstallieren Sie %s manuell und versuchen Sie es erneut." fullword wide
    $s3  = "Failed to extract VCRT64 MSI File Name from ini. Hence using default MSI name %s." fullword wide
    $s4  = "English=Acrobat DC encountered an error during installation. Please manually uninstall %s and retry." fullword wide
    $s5  = "Hebrew=Acrobat DC encountered an error during installation. Please manually uninstall %s and retry." fullword wide
    $s6  = " stato rilevato un errore da Acrobat DC durante l'installazione. Disinstallate manualmente %s e riprovate." fullword wide
    $s7  = "Danish=Der opstod en fejl i Acrobat DC under installationen. Afinstaller %s, og pr" fullword wide
    $s8  = "AFailed to register value: " fullword wide
    $s9  = "Dutch=Acrobat DC heeft een fout ontdekt tijdens de installatie. Verwijder de installatie van %s handmatig en probeer het opnieuw" wide
    $s10 = "Norwegian=Det oppstod en feil under installasjonen av Acrobat DC. Avinstaller %s manuelt, og pr" fullword wide
    $s11 = "Portuguese=O Acrobat DC encontrou um erro durante a instala" fullword wide
    $s12 = "Spanish=Acrobat DC ha encontrado un error durante la instalaci" fullword wide
    $s13 = "r Acrobat DC installerades. Avinstallera %s manuellt och f" fullword wide
    $s14 = "Invalid value entered for field Require64BitVCRT in INI file" fullword wide
    $s15 = " Acrobat DC " fullword wide
    $s16 = "hem instalace aplikace Acrobat DC do" fullword wide
    $s17 = "Hungarian=Az Acrobat DC hib" fullword wide
    $s18 = "cie Acrobat DC sa vyskytla chyba. Odin" fullword wide
    $s19 = "Slovenian=Acrobat DC je med name" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}