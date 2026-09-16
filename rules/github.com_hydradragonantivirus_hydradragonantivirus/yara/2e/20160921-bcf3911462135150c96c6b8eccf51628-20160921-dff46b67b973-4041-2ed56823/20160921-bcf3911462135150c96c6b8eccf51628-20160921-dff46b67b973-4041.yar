rule _20160921_bcf3911462135150c96c6b8eccf51628_20160921_dff46b67b973_4041 {
  meta:
    description = "datamaliciousorder - from files 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "rn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s2 = "tion f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s3 = "turn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii
    $s6 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}