rule TTP_XOR_QUAD_CurrentVersionRun_fb2a {
  strings:
    $key_fb2a = { a8 45 [2] 8c 4b [2] a7 67 [2] 89 45 [2] 9d 5e [2] 92 44 [2] 8c 59 [2] 8e 58 [2] 95 5e [2] 89 59 [2] 95 76 }

  condition:
    any of them
}