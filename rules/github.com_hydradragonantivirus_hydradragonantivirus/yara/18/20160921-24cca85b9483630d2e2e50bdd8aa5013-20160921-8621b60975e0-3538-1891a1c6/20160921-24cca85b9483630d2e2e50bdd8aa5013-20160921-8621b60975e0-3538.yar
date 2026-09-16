rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_8621b60975e0_3538 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash4       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash5       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"

  strings:
    $s1 = "tion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s2 = "000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br" ascii
    $s3 = "(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s4 = "n \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(fu" ascii
    $s5 = "n f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s6 = "function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}