rule TTP_XOR_QUAD_CurrentVersionRun_fb25 {
  strings:
    $key_fb25 = { a8 4a [2] 8c 44 [2] a7 68 [2] 89 4a [2] 9d 51 [2] 92 4b [2] 8c 56 [2] 8e 57 [2] 95 51 [2] 89 56 [2] 95 79 }

  condition:
    any of them
}