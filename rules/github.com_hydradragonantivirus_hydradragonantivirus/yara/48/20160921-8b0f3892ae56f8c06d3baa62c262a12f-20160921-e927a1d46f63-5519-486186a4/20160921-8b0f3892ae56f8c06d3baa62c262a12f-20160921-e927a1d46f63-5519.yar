rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_e927a1d46f63_5519 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"R" ascii
    $s2 = "eturn \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(" ascii
    $s3 = "000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh" ascii
    $s4 = "n f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tb" ascii
    $s5 = "(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}