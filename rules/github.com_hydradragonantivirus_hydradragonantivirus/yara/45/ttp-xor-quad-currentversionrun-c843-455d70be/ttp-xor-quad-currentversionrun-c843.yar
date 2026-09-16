rule TTP_XOR_QUAD_CurrentVersionRun_c843 {
  strings:
    $key_c843 = { 9b 2c [2] bf 22 [2] 94 0e [2] ba 2c [2] ae 37 [2] a1 2d [2] bf 30 [2] bd 31 [2] a6 37 [2] ba 30 [2] a6 1f }

  condition:
    any of them
}