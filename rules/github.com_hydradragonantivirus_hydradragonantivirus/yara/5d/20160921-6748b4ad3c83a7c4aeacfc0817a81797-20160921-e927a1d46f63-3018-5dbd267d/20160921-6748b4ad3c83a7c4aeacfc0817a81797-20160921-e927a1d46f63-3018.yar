rule _20160921_6748b4ad3c83a7c4aeacfc0817a81797_20160921_e927a1d46f63_3018 {
  meta:
    description = "datamaliciousorder - from files 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = "n \"GGn\";})(),(function f000(){return \"PLy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s2 = "urn \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(f" ascii
    $s3 = "\"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(fun" ascii
    $s4 = "function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000(){r" ascii
    $s5 = "f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Oe" ascii
    $s6 = "return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})()" ascii
    $s7 = "g\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}