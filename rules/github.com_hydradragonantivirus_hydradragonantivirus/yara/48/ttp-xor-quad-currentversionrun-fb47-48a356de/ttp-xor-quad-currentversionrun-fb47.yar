rule TTP_XOR_QUAD_CurrentVersionRun_fb47 {
  strings:
    $key_fb47 = { a8 28 [2] 8c 26 [2] a7 0a [2] 89 28 [2] 9d 33 [2] 92 29 [2] 8c 34 [2] 8e 35 [2] 95 33 [2] 89 34 [2] 95 1b }

  condition:
    any of them
}