rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_b7400937fc4e_2773 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1 = "return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Rh\";})()" ascii
    $s2 = ",(function f000(){return \"Ml\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){r" ascii
    $s3 = "00(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\"" ascii
    $s4 = "GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(funct" ascii
    $s5 = "(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";}" ascii
    $s6 = "\"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s7 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}