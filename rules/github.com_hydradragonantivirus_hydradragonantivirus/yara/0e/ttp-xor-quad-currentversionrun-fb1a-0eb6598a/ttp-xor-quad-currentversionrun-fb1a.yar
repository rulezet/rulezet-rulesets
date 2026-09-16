rule TTP_XOR_QUAD_CurrentVersionRun_fb1a {
  strings:
    $key_fb1a = { a8 75 [2] 8c 7b [2] a7 57 [2] 89 75 [2] 9d 6e [2] 92 74 [2] 8c 69 [2] 8e 68 [2] 95 6e [2] 89 69 [2] 95 46 }

  condition:
    any of them
}