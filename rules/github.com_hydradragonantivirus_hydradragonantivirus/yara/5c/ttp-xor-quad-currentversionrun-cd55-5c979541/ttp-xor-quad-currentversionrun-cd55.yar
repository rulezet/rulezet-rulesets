rule TTP_XOR_QUAD_CurrentVersionRun_cd55 {
  strings:
    $key_cd55 = { 9e 3a [2] ba 34 [2] 91 18 [2] bf 3a [2] ab 21 [2] a4 3b [2] ba 26 [2] b8 27 [2] a3 21 [2] bf 26 [2] a3 09 }

  condition:
    any of them
}