rule _20160921_bcf3911462135150c96c6b8eccf51628_20160921_d6eab67b6b3c_3132 {
  meta:
    description = "datamaliciousorder - from files 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s2 = "0(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\"" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii
    $s4 = "){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s5 = "nction f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii
    $s6 = "\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f" ascii
    $s7 = "ion f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}