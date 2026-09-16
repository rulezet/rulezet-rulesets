rule TTP_XOR_QUAD_CurrentVersionRun_fb17 {
  strings:
    $key_fb17 = { a8 78 [2] 8c 76 [2] a7 5a [2] 89 78 [2] 9d 63 [2] 92 79 [2] 8c 64 [2] 8e 65 [2] 95 63 [2] 89 64 [2] 95 4b }

  condition:
    any of them
}