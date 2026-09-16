rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_6b34f0b83cb5_3729 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"

  strings:
    $s1 = "turn \"ZGq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2 = "tion f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return" ascii
    $s4 = "Ux\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function" ascii
    $s5 = "tion f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s6 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}