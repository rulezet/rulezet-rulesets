rule _Trojan_Danger_Generic_Dacic_F7D02F69_A_18899E21_Trojan_Hooker_W_232 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Generic.Dacic.F7D02F69.A.18899E21.vir, Trojan.Hooker_Win32.Floxif.A_23_1.vir, Trojan.Hooker_Win32.Floxif.A_26_1.vir, Trojan.Hooker_Win32.Floxif.A_27_1.vir, Trojan.Hooker_Win32.Floxif.A_28_1.vir, Trojan.Hooker_Win32.Floxif.A_29_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_14_2.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_50_2.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_51_2.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_52_2.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_53_2.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_54_2.vir, Virus.Infector_Gen.Variant.Ransom.VirLock.124.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.4FE5953A.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.6E6955D6.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.9CC6DE50.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.9CC6DE50_1.vir, Virus.Infector_Generic.Dacic.F7D02F69.A.C07D8E29.vir, Virus.Infector_Trojan.AgentWDCR.PZN.vir, Virus.Infector_Win32.Worm.LightMoon.A@mm.vir, Virus.Infector_Win32.Worm.LightMoon.A@mm_1.vir, Virus.Infector_Win32.Worm.LightMoon.A@mm_2.vir, Virus.Infector_Win32.Worm.LightMoon.A@mm_3.vir, Virus.Infector_Win32.Worm.LightMoon.A@mm_4.vir"
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
    hash8       = "2891576429292fb0b76662feb7f98505d5f16b1197bdf02b4f68d47029ecb46d"
    hash9       = "17d6fe12aa14bd93643f94caf84065255720341e1e831ad72d6c746a1538f805"
    hash10      = "958be23bb096e7e29e5913a1e0856dc1428d1c9e81963d869e4eb40f49ca36d0"
    hash11      = "76645521619a4a355b7f7610deb295e11b19adf9dd5f19b90aecaccdc92389db"
    hash12      = "1ee467d3cec9c16eafaf65713916621d25454921132069dfedb1fdd8f45a45cc"
    hash13      = "8392be5c2f98d15d87a44abe6ec1709e7b89749e6eb2ea5b1f169d1ad9029600"
    hash14      = "0032e485c64168dd58e0ec5e8afb37836f9c7870fe24a6fbe6a47e103444065f"
    hash15      = "70189789556cc3a3aa791c431614375288a92ce68baeed199b16c65793bbb242"
    hash16      = "2eb79e0691385f5b168618d3345702e96577c649f99db013aa30a4b7e4554e4d"
    hash17      = "73648faead393dc249d771adf4a2336290c3c3bc4372d1eefd8d57d404a0b5b6"
    hash18      = "3b00282757d1039c8a8308cac304b57db7f732aa51fae514ae539a1d3c723918"
    hash19      = "27475b4d2067e2bf140ca63866c66cb294ea8bb55a83220ea3fb9825278a71a6"
    hash20      = "24b3b1a964fdf4334a5ca8a8aaebb9318c488658ab9fea345781faabc1d846f6"
    hash21      = "b2d1f6c2e1f7c5f090b23e02f91fe8f0c46aeeffa7207906802ae56108775f36"
    hash22      = "bf01d7204ee73d6b9fc1ccbcd7747aae5e96065a37cf68d6b378f13059f6e919"
    hash23      = "9d31cc5162741f8de00b2e19abb7e668f597279add0664a7c270db423f1d94ba"
    hash24      = "fe34451c47b96049b034587ef2fb50cdd1335394a2ea7ba785e6bc05ce2126d5"

  strings:
    $s1  = "Icon Cool-Editor 3.4.30315.exe" fullword wide
    $s2  = "Vista Transformation Pack 4.0.exe" fullword wide
    $s3  = "Content-Disposition: attachment; " fullword wide
    $s4  = "please read again what i have written to you" fullword wide
    $s5  = "Windows Sockets Version " fullword wide
    $s6  = "Enter the comment" fullword wide
    $s7  = "oh ya aku tahu anda dr milis ilmu komputer" fullword wide
    $s8  = "di lampiran ini terdapat curriculum vittae dan foto saya" fullword wide
    $s9  = " alias mysound" fullword wide
    $s10 = "Alumni Smansa" fullword wide
    $s11 = "From: <" fullword wide
    $s12 = "foto dan data Wanita tsb Thank's " fullword wide
    $s13 = "NB:Mohon di teruskan kesahabat anda " fullword wide
    $s14 = "Fucking With Me :D" fullword wide
    $s15 = "miss Indonesian" fullword wide
    $s16 = "play mySound" fullword wide
    $s17 = "dan cara menggunakan email mass" fullword wide
    $s18 = "{shift}" fullword wide
    $s19 = "{pause}" fullword wide
    $s20 = "relay." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}