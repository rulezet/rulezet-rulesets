rule TTP_XOR_QUAD_CurrentVersionRun_dc43 {
  strings:
    $key_dc43 = { 8f 2c [2] ab 22 [2] 80 0e [2] ae 2c [2] ba 37 [2] b5 2d [2] ab 30 [2] a9 31 [2] b2 37 [2] ae 30 [2] b2 1f }

  condition:
    any of them
}