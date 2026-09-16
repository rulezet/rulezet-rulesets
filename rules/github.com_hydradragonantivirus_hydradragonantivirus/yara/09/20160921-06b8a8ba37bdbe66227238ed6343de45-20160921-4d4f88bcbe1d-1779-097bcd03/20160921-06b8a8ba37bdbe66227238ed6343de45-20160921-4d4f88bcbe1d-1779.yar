rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_4d4f88bcbe1d_1779 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"

  strings:
    $s1  = "0(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\"" ascii
    $s2  = "00(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s3  = "BQb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s4  = "Pt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s5  = "0(){return \"BIj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";}" ascii
    $s6  = "f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s7  = " f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do" ascii
    $s8  = "000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s9  = "rn \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(fun" ascii
    $s10 = "0(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}