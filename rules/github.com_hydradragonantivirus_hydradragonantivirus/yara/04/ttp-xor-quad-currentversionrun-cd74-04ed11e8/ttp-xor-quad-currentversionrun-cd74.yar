rule TTP_XOR_QUAD_CurrentVersionRun_cd74 {
  strings:
    $key_cd74 = { 9e 1b [2] ba 15 [2] 91 39 [2] bf 1b [2] ab 00 [2] a4 1a [2] ba 07 [2] b8 06 [2] a3 00 [2] bf 07 [2] a3 28 }

  condition:
    any of them
}