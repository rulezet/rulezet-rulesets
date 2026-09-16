rule _20160921_5d76de82063e28ac2a0fc9a6ce296761_20160922_41319625a334_1726 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash2       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1  = "turn \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s2  = "),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s3  = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f00" ascii
    $s4  = "on f000(){return \"Qa\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s5  = "ction f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s6  = "(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";}" ascii
    $s7  = "(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){" ascii
    $s8  = "f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GG" ascii
    $s9  = " \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(funct" ascii
    $s10 = "turn \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()," ascii
    $s11 = "000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}