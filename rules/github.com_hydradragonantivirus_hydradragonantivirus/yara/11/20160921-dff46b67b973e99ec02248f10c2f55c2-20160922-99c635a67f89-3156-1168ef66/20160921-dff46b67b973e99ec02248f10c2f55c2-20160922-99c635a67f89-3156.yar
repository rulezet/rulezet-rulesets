rule _20160921_dff46b67b973e99ec02248f10c2f55c2_20160922_99c635a67f89_3156 {
  meta:
    description = "datamaliciousorder - from files 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"" ascii
    $s2 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f" ascii
    $s3 = "urn \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})()," ascii
    $s4 = "nction f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s5 = "nction f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii
    $s6 = "eturn \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})()" ascii
    $s7 = "0(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}