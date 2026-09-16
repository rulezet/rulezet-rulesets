rule _20160921_9388afe79f2f7fe198cc289c492b310f_20160921_ccabe4fce99c_5553 {
  meta:
    description = "datamaliciousorder - from files 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"
    hash4       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";" ascii
    $s2 = "tion f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s3 = "{return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})" ascii
    $s4 = "t\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function " ascii
    $s5 = "unction f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}