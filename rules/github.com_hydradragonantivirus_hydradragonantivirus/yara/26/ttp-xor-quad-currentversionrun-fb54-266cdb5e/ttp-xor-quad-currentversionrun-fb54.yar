rule TTP_XOR_QUAD_CurrentVersionRun_fb54 {
  strings:
    $key_fb54 = { a8 3b [2] 8c 35 [2] a7 19 [2] 89 3b [2] 9d 20 [2] 92 3a [2] 8c 27 [2] 8e 26 [2] 95 20 [2] 89 27 [2] 95 08 }

  condition:
    any of them
}