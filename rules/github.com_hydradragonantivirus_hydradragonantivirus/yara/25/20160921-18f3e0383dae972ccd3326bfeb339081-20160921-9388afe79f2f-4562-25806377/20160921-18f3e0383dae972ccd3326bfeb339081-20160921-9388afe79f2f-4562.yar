rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_9388afe79f2f_4562 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s2 = "unction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){ret" ascii
    $s3 = "function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){ret" ascii
    $s4 = "ion f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s5 = "return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}