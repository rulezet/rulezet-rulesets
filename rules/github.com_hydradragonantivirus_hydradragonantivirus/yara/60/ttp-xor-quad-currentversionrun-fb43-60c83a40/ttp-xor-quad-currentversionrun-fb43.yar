rule TTP_XOR_QUAD_CurrentVersionRun_fb43 {
  strings:
    $key_fb43 = { a8 2c [2] 8c 22 [2] a7 0e [2] 89 2c [2] 9d 37 [2] 92 2d [2] 8c 30 [2] 8e 31 [2] 95 37 [2] 89 30 [2] 95 1f }

  condition:
    any of them
}