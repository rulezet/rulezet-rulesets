import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_246_2_Tro_304 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_246_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_247_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_248_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_249_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_250_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_251_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_252_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_257_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_25_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_16_1.vir, Virus.Sysbot_Trojan.GenericKD.71671752_35_1.vir, Virus.Sysbot_Trojan.GenericKD.71671752_39_1.vir, Virus.Sysbot_Trojan.GenericKD.71671752_40_1.vir, Virus.Sysbot_Trojan.GenericKD.71671752_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c16e1267f1f1c0085cbbd20eda3fd5c6330c7083c89963cecb17d1371ef4e103"
    hash2       = "a6e55cf55d07766fcf447ff4f9e67573c6fe7eeaeb83fd829f6e1042b8db5114"
    hash3       = "4211b78170b97754543dbf712f91da512e5f2361471d7cff1dd74b9a3c7ab613"
    hash4       = "d88133d7ec58fade6fc5791b8b1ff4fb4952cadf41da2e8082fc41bea5110da2"
    hash5       = "49a344e5002bb1b35a0a5db1c82358c43de798acfd0192a88dc11245de163bd8"
    hash6       = "5f656f8338cbac58900aa1a578e2dab0a364c725baf788106610f998de761eb4"
    hash7       = "1e9339a726c8ec25f37641270d164c89e1a48a5aa13fdb33141fbc2723624671"
    hash8       = "dfa72cfd2cf8b1c3beac907a91042e344a301923e8e40b88541e850161eae6eb"
    hash9       = "d560989b72c8865777a83f4c2b920b715497399576c01aeb96c63e0191c794a5"
    hash10      = "d8c845678c36f965bdb5a99b36e8eb9f92a71b24e5b4d3a73611f0087449313c"
    hash11      = "ddafb0b0afb29fc2ca47c0307de65b46097dc578d7197996e27bc331d6a5b1e1"
    hash12      = "0c853e4c65538f0e06f35fb7155f393ed9086c2f7f300ee65d2ae37938b949f0"
    hash13      = "dcea2e3f590f675b9d83f8c508bbe85ef521ed51ebfc6d3ea90cd8f0d23358c5"
    hash14      = "7c1c972f058bd07c1b40b438e02744508eebbc081ecedbf9a530fee20bce4475"

  strings:
    $s1  = "server=121.42.154.95; user id=zhhwl; password=zhhwl; database=zhhwl.com;Charset=utf8;" fullword wide
    $s2  = "AMap.service([\"AMap.PlaceSearch\"], function() {var placeSearch = new AMap.PlaceSearch({  pageSize: 5,pageIndex: 1,city: \"010" wide
    $s3  = "SELECT COUNT( * ) FROM information_schema.TABLES WHERE table_name = '" fullword wide
    $s4  = "` (`id` int(10) NOT NULL AUTO_INCREMENT, `time` datetime DEFAULT NULL,`currentstatus` varchar(255) DEFAULT NULL,`startLoc` varch" wide
    $s5  = "(\\\"(?<key>[^\\\"]+)\\\":\\\"(?<value>[^,\\\"]*)\\\")|(\\\"(?<key>[^\\\"]+)\\\":(?<value>[^,\\\"\\}]*))" fullword wide
    $s6  = "urlencode(\"#number#=" fullword wide
    $s7  = "CREATE TABLE IF NOT EXISTS `" fullword wide
    $s8  = "SELECT id AS '" fullword wide
    $s9  = "', time AS '" fullword wide
    $s10 = " ORDER BY time DESC" fullword wide
    $s11 = "SELECT endLoc, senderinfo FROM " fullword wide
    $s12 = " WHERE id = 1" fullword wide
    $s13 = "' WHERE id = 1;" fullword wide
    $s14 = " WHERE id = " fullword wide
    $s15 = "alert('FFFFFFFFFFFUUUUUUUUUUCCCCCCCCCCCCCC');" fullword wide
    $s16 = "(\\\"(?<value>[^,\\\"]+)\")|(?<value>[^,\\[\\]]+)" fullword wide
    $s17 = "@semicolon" fullword wide
    $s18 = "@comma" fullword wide
    $s19 = "(time, currentstatus, startLoc, endLoc, senderinfo) VALUES('" fullword wide
    $s20 = "', time = '" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}