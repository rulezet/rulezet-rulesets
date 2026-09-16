rule TTP_XOR_QUAD_CurrentVersionRun_cd23 {
  strings:
    $key_cd23 = { 9e 4c [2] ba 42 [2] 91 6e [2] bf 4c [2] ab 57 [2] a4 4d [2] ba 50 [2] b8 51 [2] a3 57 [2] bf 50 [2] a3 7f }

  condition:
    any of them
}