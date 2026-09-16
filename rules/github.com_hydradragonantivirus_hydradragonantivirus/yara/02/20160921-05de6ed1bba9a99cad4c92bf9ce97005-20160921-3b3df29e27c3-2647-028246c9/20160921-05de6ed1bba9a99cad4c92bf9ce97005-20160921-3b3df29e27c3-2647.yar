rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_3b3df29e27c3_2647 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";}" ascii
    $s2 = "i\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s3 = "(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";}" ascii
    $s4 = "\"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(funct" ascii
    $s5 = "(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s6 = " \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(funct" ascii
    $s7 = "),(function f000(){return \"Uo\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}