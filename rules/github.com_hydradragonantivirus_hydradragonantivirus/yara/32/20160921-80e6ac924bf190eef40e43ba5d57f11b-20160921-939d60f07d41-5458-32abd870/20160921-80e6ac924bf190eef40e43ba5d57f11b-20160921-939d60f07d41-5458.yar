rule _20160921_80e6ac924bf190eef40e43ba5d57f11b_20160921_939d60f07d41_5458 {
  meta:
    description = "datamaliciousorder - from files 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1 = " f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KX" ascii
    $s2 = "nction f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s3 = "n\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s4 = "n f000(){return \"IAa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"M" ascii
    $s5 = "(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}