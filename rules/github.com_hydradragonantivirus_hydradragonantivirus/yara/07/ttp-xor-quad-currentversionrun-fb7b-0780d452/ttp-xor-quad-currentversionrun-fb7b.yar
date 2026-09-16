rule TTP_XOR_QUAD_CurrentVersionRun_fb7b {
  strings:
    $key_fb7b = { a8 14 [2] 8c 1a [2] a7 36 [2] 89 14 [2] 9d 0f [2] 92 15 [2] 8c 08 [2] 8e 09 [2] 95 0f [2] 89 08 [2] 95 27 }

  condition:
    any of them
}