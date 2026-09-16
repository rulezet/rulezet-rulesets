rule TTP_XOR_QUAD_CurrentVersionRun_cd75 {
  strings:
    $key_cd75 = { 9e 1a [2] ba 14 [2] 91 38 [2] bf 1a [2] ab 01 [2] a4 1b [2] ba 06 [2] b8 07 [2] a3 01 [2] bf 06 [2] a3 29 }

  condition:
    any of them
}