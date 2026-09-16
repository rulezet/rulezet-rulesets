rule _Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_10_1_Virus_Hija_414 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_4_2.vir, Virus.Infector_Gen.Trojan.Malware.Mq3@aunLb5ni_3.vir, Virus.Infector_Win32.Expiro.Gen.7_14.vir, Virus.Infector_Win32.Expiro.Gen.7_168.vir, Virus.Infector_Win32.Expiro.Gen.7_76.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2652570e9cf13b161f216a83f6a0555fb4c649835b2565250d4b0d683a3b0ca3"
    hash2       = "2dddbc1089ad69bb03732354ada2b7e0ce139ef6cbdb635c07af38b138c62903"
    hash3       = "b7031bd32f110b3183848fc7a05313bbfd2581936c862e20d7c5b63fb8e60cde"
    hash4       = "6555be611cce503c4e1cc2969421d56e9239921768c8a91d6c47b1f7718b4774"
    hash5       = "507ed733d403facb83600e8d149cbe641f990c067a024ac7db9a5ed7b93456de"
    hash6       = "ec794ca56580bf29eb3f54d2ffbc34d07284edfb9eac5895a22c7fa1e19310db"

  strings:
    $s1 = " Office Conflict Wizard</description>" fullword ascii
    $s2 = "SOFTWARE\\Microsoft\\Office\\12.0\\Access Connectivity Engine\\InstallRoot" fullword wide
    $s3 = "Previous instance already running. Spec issue under consideration to not allow this." fullword wide
    $s4 = "Invoke Failed with error " fullword wide
    $s5 = "CnfWiz ASSERTION FAILURE" fullword wide
    $s6 = "MsgBox insert without a corresponding string ID (modMain.IMsgBox)" fullword wide
    $s7 = "Replication Conflict Viewer" fullword ascii
    $s8 = "-Replication Conflict Viewer" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}