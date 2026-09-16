rule _20160921_5d76de82063e28ac2a0fc9a6ce296761_20160921_8a6f0879f250_2466 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "eturn \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";" ascii
    $s3 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return " ascii
    $s4 = "eturn \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"YTp\";})()," ascii
    $s5 = "ction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){retur" ascii
    $s6 = "(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"XTn\";" ascii
    $s7 = "n f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s8 = "f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}