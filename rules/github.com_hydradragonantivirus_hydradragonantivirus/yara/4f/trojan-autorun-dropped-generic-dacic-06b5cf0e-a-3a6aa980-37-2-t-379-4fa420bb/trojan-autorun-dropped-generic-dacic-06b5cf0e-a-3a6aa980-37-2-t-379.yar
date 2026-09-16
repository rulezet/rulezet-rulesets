rule _Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_37_2_T_379 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_37_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_49_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_62_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_72_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_73_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_74_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_75_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_8_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_350_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_196_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_9_1.vir, VirusShareBackDoorBladabindi13678_1_1.vir, VirusShareTrojanInject36111_22_1.vir, VirusShareTrojanInject36111_23_1.vir, VirusShareTrojanInject36111_24_1.vir, VirusShareTrojanInject36111_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d78a626a36559da75eca7cb8e62e5e1c872633246a8ec664700dc968efc71f24"
    hash2       = "80a48ecd98c59c948b747df15857a32f997d39970f1a330affdc32178feeb1b6"
    hash3       = "ebd2b93e91ff2f27de81b69d75ec29e6347cf8826db840b77f48f67f6f013f84"
    hash4       = "be7d16cefc8ea997352189dff9425572e853027acf013738e06644a843755e0b"
    hash5       = "c7cd1a882672e712d50fe748f3cfff4ebbf78455d00183005212eb4028b66d78"
    hash6       = "df231158afb377a5f5a2d0ecfb130d26cc0123762bcef1c7c3ba8b36f2dba0ba"
    hash7       = "79fc47434aec38f3f72dcb8f657b805d4462e227d4dff3345673151b07a5ca6f"
    hash8       = "75e4b3f37cb5b760e630603ac21a338cb134380dabbd674a9520045bd4e4da97"
    hash9       = "322b52e9282d7f023a377a91eafe24dccfe259449c78502614fc381bacd92ac4"
    hash10      = "6201208eba385c0e8c979af1beb041f695bf86dc459a8877c31099a00ebf5970"
    hash11      = "b16cd8b43deee2443c27a14a3a1d9a885ad233cf8fec3a4e14b9a760c8a5e3ab"
    hash12      = "98fda289113d05f1de709871f358eb316e4c24f4c7d75014da98f91cc96909fc"
    hash13      = "0f411fca3429c794c6261ce872f15529d2fefc9a002cc52b4669d5e7f59198a2"
    hash14      = "2815c7fda26e891ef2b0b29f223604415b1d6dec8bd551c2d96c2b3ac795a001"
    hash15      = "f82b943fcb4c26ae04886872a5f78a0cdc0a4ee75b301e69bedebbfb07dcd4b0"
    hash16      = "1ad569cc938b75d3b2a4a7afc4c7f9da55e4e0ef7054bc30957d0346d8ae8422"
    hash17      = "6439ed7d93a3e2bae153bbc84b22088d76c461f67b68a842bdc75efbec17f0d3"
    hash18      = "fc503192818617738ef71f55ba64ada4f60353b12dfdaedb481534e7d43b314f"

  strings:
    $s1 = "Yasimecehel fogawev zoyisetujaserej. Figupo. Pib xifiyezuribix. Diko zojaci guboxawiruwojo vibowejiyul mulawupefo. Cila serutene" ascii
    $s2 = "l. Kusu vezunat. Vohaloweyojal fabuxunayu. Dawadekifoco. Xixiyejobamuc hikuter. Voziyipuwijuj tulozako ferutogahoduku yaje. Coh " ascii
    $s3 = ". Gevetol wupadefitimavi. Bezufahekebuy gum yuhenapudewa. Vumubilet sib limi wudir xux. Vile fesuhos xawih tarebotug ribugewigin" ascii
    $s4 = "agevifuj roleheyovuwobil hukedihu. Wime wawosofidejiv corimacipeguyo. Yovomasu yec vibidu govusel. Xuz paj fuyu joyanu. Nafayabu" ascii
    $s5 = " pazoxo. Godih juwemif jato nubadezabox. Cezuyuruje vewetono dul wojewigiwexogay. Pule. Gunubecewen jiki tok tofes sabiraf. Bame" ascii
    $s6 = "pupa nihuyepo mowotig woruhatodupew. Siz cuwosoxa tiredowalibu gasoharuj. Xip. Yudujip cecuyogavisezat conahidavisopus. Kafusado" ascii
    $s7 = "humoya diho fiz jofevo reliripitut. Humoxoyudisut situbexuyijo xuvixasavub wecaxuruzadeha dopahaxitosin. Pino denoter yadogog ge" ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}