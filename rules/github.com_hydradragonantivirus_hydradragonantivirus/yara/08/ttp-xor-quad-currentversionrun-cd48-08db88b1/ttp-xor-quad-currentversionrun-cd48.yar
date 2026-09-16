rule TTP_XOR_QUAD_CurrentVersionRun_cd48 {
  strings:
    $key_cd48 = { 9e 27 [2] ba 29 [2] 91 05 [2] bf 27 [2] ab 3c [2] a4 26 [2] ba 3b [2] b8 3a [2] a3 3c [2] bf 3b [2] a3 14 }

  condition:
    any of them
}