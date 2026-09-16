rule _20160921_02b826231ece268e91633311d2c70554_20160922_99c635a67f89_4141 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb" ascii
    $s3 = "n \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s4 = "{return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "n \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}