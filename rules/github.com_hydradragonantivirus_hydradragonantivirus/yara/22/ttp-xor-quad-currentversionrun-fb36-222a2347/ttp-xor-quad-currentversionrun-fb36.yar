rule TTP_XOR_QUAD_CurrentVersionRun_fb36 {
  strings:
    $key_fb36 = { a8 59 [2] 8c 57 [2] a7 7b [2] 89 59 [2] 9d 42 [2] 92 58 [2] 8c 45 [2] 8e 44 [2] 95 42 [2] 89 45 [2] 95 6a }

  condition:
    any of them
}