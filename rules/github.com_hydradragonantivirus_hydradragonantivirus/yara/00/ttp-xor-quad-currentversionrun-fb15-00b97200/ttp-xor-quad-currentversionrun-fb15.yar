rule TTP_XOR_QUAD_CurrentVersionRun_fb15 {
  strings:
    $key_fb15 = { a8 7a [2] 8c 74 [2] a7 58 [2] 89 7a [2] 9d 61 [2] 92 7b [2] 8c 66 [2] 8e 67 [2] 95 61 [2] 89 66 [2] 95 49 }

  condition:
    any of them
}