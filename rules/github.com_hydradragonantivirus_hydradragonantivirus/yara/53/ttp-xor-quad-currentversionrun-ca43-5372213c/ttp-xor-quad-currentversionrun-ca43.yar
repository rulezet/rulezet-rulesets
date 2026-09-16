rule TTP_XOR_QUAD_CurrentVersionRun_ca43 {
  strings:
    $key_ca43 = { 99 2c [2] bd 22 [2] 96 0e [2] b8 2c [2] ac 37 [2] a3 2d [2] bd 30 [2] bf 31 [2] a4 37 [2] b8 30 [2] a4 1f }

  condition:
    any of them
}