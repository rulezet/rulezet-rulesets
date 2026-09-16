rule TTP_XOR_QUAD_CurrentVersionRun_fb0b {
  strings:
    $key_fb0b = { a8 64 [2] 8c 6a [2] a7 46 [2] 89 64 [2] 9d 7f [2] 92 65 [2] 8c 78 [2] 8e 79 [2] 95 7f [2] 89 78 [2] 95 57 }

  condition:
    any of them
}