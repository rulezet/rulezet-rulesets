rule TTP_XOR_QUAD_CurrentVersionRun_d343 {
  strings:
    $key_d343 = { 80 2c [2] a4 22 [2] 8f 0e [2] a1 2c [2] b5 37 [2] ba 2d [2] a4 30 [2] a6 31 [2] bd 37 [2] a1 30 [2] bd 1f }

  condition:
    any of them
}