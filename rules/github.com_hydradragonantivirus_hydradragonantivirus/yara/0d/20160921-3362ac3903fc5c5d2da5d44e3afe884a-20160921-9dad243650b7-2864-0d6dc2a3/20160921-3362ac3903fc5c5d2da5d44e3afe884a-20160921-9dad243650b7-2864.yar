rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_9dad243650b7_2864 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_9dad243650b7872772e7037b467b5a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"

  strings:
    $s1 = "Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s2 = "(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";}" ascii
    $s3 = "(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";" ascii
    $s4 = "(function f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OMd\";})(),(function f000(){r" ascii
    $s5 = "urn \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s6 = "n f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"K" ascii
    $s7 = "000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}