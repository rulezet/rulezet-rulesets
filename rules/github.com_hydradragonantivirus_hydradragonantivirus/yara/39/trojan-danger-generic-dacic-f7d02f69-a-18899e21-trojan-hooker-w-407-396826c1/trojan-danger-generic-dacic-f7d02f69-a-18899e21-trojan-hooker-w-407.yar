rule _Trojan_Danger_Generic_Dacic_F7D02F69_A_18899E21_Trojan_Hooker_W_407 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Generic.Dacic.F7D02F69.A.18899E21.vir, Trojan.Hooker_Win32.Floxif.A_23_1.vir, Trojan.Hooker_Win32.Floxif.A_26_1.vir, Trojan.Hooker_Win32.Floxif.A_27_1.vir, Trojan.Hooker_Win32.Floxif.A_28_1.vir, Trojan.Hooker_Win32.Floxif.A_29_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_14_2.vir, Virus.Infector_Gen.Variant.Ransom.VirLock.124.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.4FE5953A.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.6E6955D6.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.9CC6DE50.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.9CC6DE50_1.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.C07D8E29.vir, Virus.Infector_Trojan.AgentWDCR.PZN.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ee0b02e765397168a696e3b732e7198fa0d2fbf61272dd7b97ad340407cbda"
    hash2       = "fe5dd322ea49272940d9cdefe9885103cde7129d24dbb0e4bd47f4a251c5e043"
    hash3       = "9e7786632e5b4cc58eab05a0a54cd54639a8f50115f397ad92c44cba90cdbcca"
    hash4       = "553771bcab6589951055ed7a7188864a3bb36eebfe8b936aa97a45e4c7b8cfc8"
    hash5       = "d02945bdb704efb635210e885aa08c517863a893e1574eec4ed4dfa4962a8d2f"
    hash6       = "a8a919aace2d8eaaf14bf142e66a5ec2da8ef2bbb50c5aca41495a335ff8f514"
    hash7       = "11d001668147c6ec2051950e4a7f2000934dabf81c4e63a42c1353c6f8b1b04e"
    hash8       = "8392be5c2f98d15d87a44abe6ec1709e7b89749e6eb2ea5b1f169d1ad9029600"
    hash9       = "0032e485c64168dd58e0ec5e8afb37836f9c7870fe24a6fbe6a47e103444065f"
    hash10      = "70189789556cc3a3aa791c431614375288a92ce68baeed199b16c65793bbb242"
    hash11      = "2eb79e0691385f5b168618d3345702e96577c649f99db013aa30a4b7e4554e4d"
    hash12      = "73648faead393dc249d771adf4a2336290c3c3bc4372d1eefd8d57d404a0b5b6"
    hash13      = "3b00282757d1039c8a8308cac304b57db7f732aa51fae514ae539a1d3c723918"
    hash14      = "27475b4d2067e2bf140ca63866c66cb294ea8bb55a83220ea3fb9825278a71a6"

  strings:
    $s1 = "<!-- Code By HellSPawN a.k.a B4BB!cool -->" fullword wide
    $s2 = "C*\\AD:\\DataHellSpawn\\WARING_VIRII_LABORATORY\\Virus Ku\\Moonlight Update Baru\\Project1.vbp" fullword wide
    $s3 = "FILE FOLDER" fullword ascii
    $s4 = "   CopyRight @ HellSpawn a.K.a B4bb1CooL" fullword wide
    $s5 = "Hacker = Asc(Mid(a, i, 1))" fullword wide
    $s6 = "crbyte = Chr(Hacker Xor (dePok Mod 12))" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}