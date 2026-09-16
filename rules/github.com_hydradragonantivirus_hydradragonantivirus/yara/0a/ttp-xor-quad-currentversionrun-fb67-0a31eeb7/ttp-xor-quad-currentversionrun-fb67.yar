rule TTP_XOR_QUAD_CurrentVersionRun_fb67 {
  strings:
    $key_fb67 = { a8 08 [2] 8c 06 [2] a7 2a [2] 89 08 [2] 9d 13 [2] 92 09 [2] 8c 14 [2] 8e 15 [2] 95 13 [2] 89 14 [2] 95 3b }

  condition:
    any of them
}