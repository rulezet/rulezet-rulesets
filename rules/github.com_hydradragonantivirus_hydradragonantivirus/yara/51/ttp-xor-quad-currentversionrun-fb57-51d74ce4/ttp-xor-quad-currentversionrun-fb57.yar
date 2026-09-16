rule TTP_XOR_QUAD_CurrentVersionRun_fb57 {
  strings:
    $key_fb57 = { a8 38 [2] 8c 36 [2] a7 1a [2] 89 38 [2] 9d 23 [2] 92 39 [2] 8c 24 [2] 8e 25 [2] 95 23 [2] 89 24 [2] 95 0b }

  condition:
    any of them
}