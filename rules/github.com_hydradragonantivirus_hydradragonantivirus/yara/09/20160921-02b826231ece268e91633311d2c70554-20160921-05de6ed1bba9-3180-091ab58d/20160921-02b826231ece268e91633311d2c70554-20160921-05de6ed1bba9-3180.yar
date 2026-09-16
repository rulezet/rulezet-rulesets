rule _20160921_02b826231ece268e91633311d2c70554_20160921_05de6ed1bba9_3180 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"

  strings:
    $s1 = "function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){retu" ascii
    $s2 = "0(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s3 = "\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"BQb\";})(),(function " ascii
    $s4 = "return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})" ascii
    $s5 = "return \"Iq\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})()," ascii
    $s6 = "000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}