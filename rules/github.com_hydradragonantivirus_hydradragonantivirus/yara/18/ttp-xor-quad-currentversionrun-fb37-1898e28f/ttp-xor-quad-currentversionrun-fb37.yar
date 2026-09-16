rule TTP_XOR_QUAD_CurrentVersionRun_fb37 {
  strings:
    $key_fb37 = { a8 58 [2] 8c 56 [2] a7 7a [2] 89 58 [2] 9d 43 [2] 92 59 [2] 8c 44 [2] 8e 45 [2] 95 43 [2] 89 44 [2] 95 6b }

  condition:
    any of them
}