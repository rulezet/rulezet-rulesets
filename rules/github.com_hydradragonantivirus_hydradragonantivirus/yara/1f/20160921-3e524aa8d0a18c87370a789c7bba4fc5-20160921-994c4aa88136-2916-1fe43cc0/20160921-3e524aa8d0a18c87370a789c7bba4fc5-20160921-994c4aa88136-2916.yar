rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_994c4aa88136_2916 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "n \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s2 = "000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\"" ascii
    $s3 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return" ascii
    $s4 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})()," ascii
    $s5 = "eturn \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(" ascii
    $s6 = "PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functi" ascii
    $s7 = "000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"NY" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}