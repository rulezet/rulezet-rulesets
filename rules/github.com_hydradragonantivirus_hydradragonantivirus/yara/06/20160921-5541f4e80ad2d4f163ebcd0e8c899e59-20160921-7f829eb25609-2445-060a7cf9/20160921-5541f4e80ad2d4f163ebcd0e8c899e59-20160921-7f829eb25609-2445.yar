rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_7f829eb25609_2445 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "rn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s2 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s3 = "tion f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s4 = "GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s5 = "urn \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})()," ascii
    $s6 = "f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj" ascii
    $s7 = "})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s8 = "){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}