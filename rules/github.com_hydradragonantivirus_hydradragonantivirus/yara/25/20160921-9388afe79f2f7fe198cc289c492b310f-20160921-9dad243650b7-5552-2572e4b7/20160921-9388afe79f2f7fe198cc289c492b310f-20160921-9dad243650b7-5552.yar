rule _20160921_9388afe79f2f7fe198cc289c492b310f_20160921_9dad243650b7_5552 {
  meta:
    description = "datamaliciousorder - from files 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash2       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"
    hash4       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s2 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s3 = "f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"G" ascii
    $s4 = "n \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sq\";})(),(fun" ascii
    $s5 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}