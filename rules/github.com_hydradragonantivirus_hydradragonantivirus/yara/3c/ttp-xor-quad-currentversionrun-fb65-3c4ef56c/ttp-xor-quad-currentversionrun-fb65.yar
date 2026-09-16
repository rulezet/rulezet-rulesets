rule TTP_XOR_QUAD_CurrentVersionRun_fb65 {
  strings:
    $key_fb65 = { a8 0a [2] 8c 04 [2] a7 28 [2] 89 0a [2] 9d 11 [2] 92 0b [2] 8c 16 [2] 8e 17 [2] 95 11 [2] 89 16 [2] 95 39 }

  condition:
    any of them
}