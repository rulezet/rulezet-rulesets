rule _20160921_e1835bc92c4604db194bc49df621cade_20160922_f0d656e55be0_4073 {
  meta:
    description = "datamaliciousorder - from files 20160921_e1835bc92c4604db194bc49df621cade.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KX" ascii
    $s3 = " \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s4 = "0(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\"" ascii
    $s5 = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s6 = " \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}