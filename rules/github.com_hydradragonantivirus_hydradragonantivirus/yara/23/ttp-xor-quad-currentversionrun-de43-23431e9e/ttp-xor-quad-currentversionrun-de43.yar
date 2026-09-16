rule TTP_XOR_QUAD_CurrentVersionRun_de43 {
  strings:
    $key_de43 = { 8d 2c [2] a9 22 [2] 82 0e [2] ac 2c [2] b8 37 [2] b7 2d [2] a9 30 [2] ab 31 [2] b0 37 [2] ac 30 [2] b0 1f }

  condition:
    any of them
}