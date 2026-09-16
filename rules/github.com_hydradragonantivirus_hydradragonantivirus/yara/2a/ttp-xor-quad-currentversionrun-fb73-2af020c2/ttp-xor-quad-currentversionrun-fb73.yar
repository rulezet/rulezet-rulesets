rule TTP_XOR_QUAD_CurrentVersionRun_fb73 {
  strings:
    $key_fb73 = { a8 1c [2] 8c 12 [2] a7 3e [2] 89 1c [2] 9d 07 [2] 92 1d [2] 8c 00 [2] 8e 01 [2] 95 07 [2] 89 00 [2] 95 2f }

  condition:
    any of them
}