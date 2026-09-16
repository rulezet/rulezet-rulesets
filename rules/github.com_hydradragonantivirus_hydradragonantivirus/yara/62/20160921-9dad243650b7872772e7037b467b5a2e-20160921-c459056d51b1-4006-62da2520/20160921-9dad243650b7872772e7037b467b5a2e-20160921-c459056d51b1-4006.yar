rule _20160921_9dad243650b7872772e7037b467b5a2e_20160921_c459056d51b1_4006 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";}" ascii
    $s2 = ";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f0" ascii
    $s3 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s4 = "ction f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s5 = "f000(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GG" ascii
    $s6 = "return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}