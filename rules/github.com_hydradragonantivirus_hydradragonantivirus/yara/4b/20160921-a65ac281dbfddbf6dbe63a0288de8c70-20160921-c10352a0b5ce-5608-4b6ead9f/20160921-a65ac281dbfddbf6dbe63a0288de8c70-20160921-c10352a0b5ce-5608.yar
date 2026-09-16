rule _20160921_a65ac281dbfddbf6dbe63a0288de8c70_20160921_c10352a0b5ce_5608 {
  meta:
    description = "datamaliciousorder - from files 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "0(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";" ascii
    $s2 = "n f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s3 = "\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})(),(function f" ascii
    $s4 = "){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s5 = "eturn \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}