rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160921_b04df6930d82_3721 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"

  strings:
    $s1 = "){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb\";}" ascii
    $s2 = "ction f000(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s3 = "ction f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return" ascii
    $s4 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Vj\";})(),(functio" ascii
    $s5 = "n \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s6 = "rn \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}