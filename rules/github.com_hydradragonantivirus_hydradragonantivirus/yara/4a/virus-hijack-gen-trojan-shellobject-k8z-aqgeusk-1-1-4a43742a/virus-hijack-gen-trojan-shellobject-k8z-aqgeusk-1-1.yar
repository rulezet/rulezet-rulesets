rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08dcb812e0f4b6f7be8ba536959f235c02c441df844b0ce818cd97b3dfeb4e32"

  strings:
    $s1 = "Wi zumede]Loci fucavoxili tuvabujupe xoyixuha pikosi hemuku xabikugikijabe sogutuyozuko nipihowu socegu'Tosixuxaco jofodagolu hi" wide
    $s2 = "Duremefulebiti neka tixe bale0Wufevujokago mihaciceyeyeva xudi zerafasumate va*Ku vokogumiwu bota hutuco zame vijiha rabe" fullword wide
    $s3 = "i dukaferaho. Domafemirocida rejaxu ladawimidu. Vita nami rogifunohabuzo novitekicole. Seni mupezumoti. Bopinecesaxi kulatebu to" ascii
    $s4 = "Xelo. Zopovuze vo. Kubomuna vepo xa. Rozuhifurajoda ci rarici vuposamize zahomasowakuzu. Kakupikiku mujagubolagijo navajigoyupor" ascii
    $s5 = "Copyright (C) 2017, tvevabhuehb" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}