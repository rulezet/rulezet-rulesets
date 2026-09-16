rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_b2002e7f99c6_5506 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn" ascii
    $s3 = "rn \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(" ascii
    $s4 = "ion f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s5 = " f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}