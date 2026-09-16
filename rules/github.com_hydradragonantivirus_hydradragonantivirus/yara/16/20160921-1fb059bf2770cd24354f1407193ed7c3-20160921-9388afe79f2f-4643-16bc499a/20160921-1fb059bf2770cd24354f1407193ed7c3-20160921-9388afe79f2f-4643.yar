rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_9388afe79f2f_4643 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1 = "0(){return \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s2 = "return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})" ascii
    $s3 = ")(),(function f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000()" ascii
    $s4 = ";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f00" ascii
    $s5 = "urn \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}