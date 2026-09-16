rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_d1c97b87a698_5455 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "rn \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s2 = "){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";}" ascii
    $s3 = "function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){ret" ascii
    $s4 = "on f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s5 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qa\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}