rule TTP_XOR_QUAD_CurrentVersionRun_fb24 {
  strings:
    $key_fb24 = { a8 4b [2] 8c 45 [2] a7 69 [2] 89 4b [2] 9d 50 [2] 92 4a [2] 8c 57 [2] 8e 56 [2] 95 50 [2] 89 57 [2] 95 78 }

  condition:
    any of them
}