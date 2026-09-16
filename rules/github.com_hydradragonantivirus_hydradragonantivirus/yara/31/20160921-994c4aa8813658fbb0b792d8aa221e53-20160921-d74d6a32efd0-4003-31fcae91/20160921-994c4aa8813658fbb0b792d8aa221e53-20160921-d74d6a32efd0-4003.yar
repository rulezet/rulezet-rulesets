rule _20160921_994c4aa8813658fbb0b792d8aa221e53_20160921_d74d6a32efd0_4003 {
  meta:
    description = "datamaliciousorder - from files 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"
    hash3       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s2 = "n \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s3 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(fu" ascii
    $s4 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(" ascii
    $s5 = "return \"Km\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(" ascii
    $s6 = "\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}