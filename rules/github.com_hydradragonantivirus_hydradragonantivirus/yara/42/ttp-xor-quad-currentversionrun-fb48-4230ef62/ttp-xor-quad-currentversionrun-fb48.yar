rule TTP_XOR_QUAD_CurrentVersionRun_fb48 {
  strings:
    $key_fb48 = { a8 27 [2] 8c 29 [2] a7 05 [2] 89 27 [2] 9d 3c [2] 92 26 [2] 8c 3b [2] 8e 3a [2] 95 3c [2] 89 3b [2] 95 14 }

  condition:
    any of them
}