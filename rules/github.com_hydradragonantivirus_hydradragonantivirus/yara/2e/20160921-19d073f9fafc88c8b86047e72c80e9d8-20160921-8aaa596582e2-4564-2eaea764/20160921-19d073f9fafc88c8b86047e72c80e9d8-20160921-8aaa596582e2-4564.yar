rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_8aaa596582e2_4564 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = ")(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s2 = "0(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\"" ascii
    $s3 = "ion f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s4 = "Rc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s5 = "{return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"RVb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}