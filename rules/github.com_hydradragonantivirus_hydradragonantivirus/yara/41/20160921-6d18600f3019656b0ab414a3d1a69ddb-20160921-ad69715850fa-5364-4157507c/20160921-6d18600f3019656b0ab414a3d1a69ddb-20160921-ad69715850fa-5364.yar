rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_ad69715850fa_5364 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TKp\";})(),(f" ascii
    $s2 = "n f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return " ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){retur" ascii
    $s4 = "on f000(){return \"Qa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s5 = "on f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}