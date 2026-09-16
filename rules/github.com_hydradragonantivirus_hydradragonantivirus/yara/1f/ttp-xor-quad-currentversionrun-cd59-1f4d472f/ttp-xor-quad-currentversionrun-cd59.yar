rule TTP_XOR_QUAD_CurrentVersionRun_cd59 {
  strings:
    $key_cd59 = { 9e 36 [2] ba 38 [2] 91 14 [2] bf 36 [2] ab 2d [2] a4 37 [2] ba 2a [2] b8 2b [2] a3 2d [2] bf 2a [2] a3 05 }

  condition:
    any of them
}