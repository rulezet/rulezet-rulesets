rule TTP_XOR_QUAD_CurrentVersionRun_c643 {
  strings:
    $key_c643 = { 95 2c [2] b1 22 [2] 9a 0e [2] b4 2c [2] a0 37 [2] af 2d [2] b1 30 [2] b3 31 [2] a8 37 [2] b4 30 [2] a8 1f }

  condition:
    any of them
}