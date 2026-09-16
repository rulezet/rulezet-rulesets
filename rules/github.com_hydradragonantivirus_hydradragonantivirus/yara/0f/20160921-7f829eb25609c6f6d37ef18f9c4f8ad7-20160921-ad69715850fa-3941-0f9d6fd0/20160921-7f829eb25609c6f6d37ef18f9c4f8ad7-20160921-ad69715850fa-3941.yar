rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_ad69715850fa_3941 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})()," ascii
    $s2 = "(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){r" ascii
    $s3 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(" ascii
    $s4 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s5 = "urn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(" ascii
    $s6 = "return \"Sq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}