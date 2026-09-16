rule TTP_XOR_QUAD_CurrentVersionRun_f543 {
  strings:
    $key_f543 = { a6 2c [2] 82 22 [2] a9 0e [2] 87 2c [2] 93 37 [2] 9c 2d [2] 82 30 [2] 80 31 [2] 9b 37 [2] 87 30 [2] 9b 1f }

  condition:
    any of them
}