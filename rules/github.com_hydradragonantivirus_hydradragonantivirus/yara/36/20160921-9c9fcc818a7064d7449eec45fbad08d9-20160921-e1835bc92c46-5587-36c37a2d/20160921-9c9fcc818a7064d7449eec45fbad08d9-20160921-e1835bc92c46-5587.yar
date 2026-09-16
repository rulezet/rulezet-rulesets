rule _20160921_9c9fcc818a7064d7449eec45fbad08d9_20160921_e1835bc92c46_5587 {
  meta:
    description = "datamaliciousorder - from files 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_e1835bc92c4604db194bc49df621cade.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash3       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s2 = "(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";}" ascii
    $s3 = "){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})" ascii
    $s4 = ";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f0" ascii
    $s5 = "ction f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}