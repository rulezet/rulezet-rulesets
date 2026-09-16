rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_994c4aa88136_4854 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash4       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IP" ascii
    $s2 = "})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000" ascii
    $s3 = "ction f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s4 = "urn \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(" ascii
    $s5 = " f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"N" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}