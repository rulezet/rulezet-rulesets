rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_25c11e2eab44_3490 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_5e3ac68b2242250176f3300039d176f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash3       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"

  strings:
    $s1 = "urn \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"B" ascii
    $s3 = "rn \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQ" ascii
    $s5 = "00(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\"" ascii
    $s6 = "unction f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}