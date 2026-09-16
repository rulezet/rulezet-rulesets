rule TTP_XOR_QUAD_CurrentVersionRun_fb78 {
  strings:
    $key_fb78 = { a8 17 [2] 8c 19 [2] a7 35 [2] 89 17 [2] 9d 0c [2] 92 16 [2] 8c 0b [2] 8e 0a [2] 95 0c [2] 89 0b [2] 95 24 }

  condition:
    any of them
}