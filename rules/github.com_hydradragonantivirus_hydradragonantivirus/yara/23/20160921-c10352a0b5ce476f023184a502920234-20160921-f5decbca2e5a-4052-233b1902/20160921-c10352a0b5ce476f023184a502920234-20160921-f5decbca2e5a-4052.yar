rule _20160921_c10352a0b5ce476f023184a502920234_20160921_f5decbca2e5a_4052 {
  meta:
    description = "datamaliciousorder - from files 20160921_c10352a0b5ce476f023184a502920234.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"
    hash2       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"

  strings:
    $s1 = "unction f000(){return \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){ret" ascii
    $s2 = "ion f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s3 = "n f000(){return \"Rh\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"" ascii
    $s4 = "{return \"YTp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s5 = " \"Yi\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s6 = "})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}