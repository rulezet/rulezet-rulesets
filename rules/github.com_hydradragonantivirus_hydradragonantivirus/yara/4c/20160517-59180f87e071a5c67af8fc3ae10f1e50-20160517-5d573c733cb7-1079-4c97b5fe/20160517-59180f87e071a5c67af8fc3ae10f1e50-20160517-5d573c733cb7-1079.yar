rule _20160517_59180f87e071a5c67af8fc3ae10f1e50_20160517_5d573c733cb7_1079 {
  meta:
    description = "datamaliciousorder - from files 20160517_59180f87e071a5c67af8fc3ae10f1e50.js, 20160517_5d573c733cb76dc5efcaedcecfcae1fe.js, 20160517_7efe89167d660827823bbe5d0ad8e241.js, 20160517_dc786089a92dd7032fe5743cf56d2f39.js, 20160517_e04b576ab218999dae7f78b4e34149f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "378b2e161239d516e83e744e1a8fc09fdafea4d921ed090421cc1caaf29c4a5c"
    hash2       = "ca9bcbc5526c7fbd27c016b5057602437e45745f04e37b7e90dd24574d7fc81b"
    hash3       = "cae106a0bec35c1e48b82717db69469843cb082357d3dbca2bed96776d21d0fe"
    hash4       = "fb9b9154d33ab657d99ac58c87bc7862112335e89d7caa02bbcfeb8432579ab8"
    hash5       = "4f4df398bb6d9a4a563af301527a52cb547a2a62a2a9b27526dc24e4acda095c"

  strings:
    $s1 = "var nConverts1 /* Q  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* Q  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* Q  */;};" fullword ascii
    $s4 = "var enjoy1 /* Q  */ = false;" fullword ascii
    $s5 = "batch =/* Q  */ \"R\" + \"esponseB\"/* Q  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "enjoy1 /* Q  */ /* Q  */= true;/* Q  */" fullword ascii
    $s7 = "could = /* Q  */(/* Q  */\"noitisop\").split(''/* Q  */).reverse(/* Q  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}