rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160922_9d6af2734812_3035 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s2 = "Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s4 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s5 = "nction f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s6 = "000(){return \"PTs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn" ascii
    $s7 = "j\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}