rule _20160921_469953d9833167e141d9f086f1f41437_20160921_be8454f98b5a_3719 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash3       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1 = "eturn \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s2 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s3 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function f" ascii
    $s4 = " \"MBg\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s5 = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck" ascii
    $s6 = "Hd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}