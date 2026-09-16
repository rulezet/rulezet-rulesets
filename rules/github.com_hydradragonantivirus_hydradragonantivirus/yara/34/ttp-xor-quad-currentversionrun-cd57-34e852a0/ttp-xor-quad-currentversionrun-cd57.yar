rule TTP_XOR_QUAD_CurrentVersionRun_cd57 {
  strings:
    $key_cd57 = { 9e 38 [2] ba 36 [2] 91 1a [2] bf 38 [2] ab 23 [2] a4 39 [2] ba 24 [2] b8 25 [2] a3 23 [2] bf 24 [2] a3 0b }

  condition:
    any of them
}