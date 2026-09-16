rule TTP_XOR_QUAD_CurrentVersionRun_fb61 {
  strings:
    $key_fb61 = { a8 0e [2] 8c 00 [2] a7 2c [2] 89 0e [2] 9d 15 [2] 92 0f [2] 8c 12 [2] 8e 13 [2] 95 15 [2] 89 12 [2] 95 3d }

  condition:
    any of them
}