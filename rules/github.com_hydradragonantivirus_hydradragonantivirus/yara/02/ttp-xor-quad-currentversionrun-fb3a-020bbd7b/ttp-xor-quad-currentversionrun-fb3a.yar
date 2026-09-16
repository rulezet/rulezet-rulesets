rule TTP_XOR_QUAD_CurrentVersionRun_fb3a {
  strings:
    $key_fb3a = { a8 55 [2] 8c 5b [2] a7 77 [2] 89 55 [2] 9d 4e [2] 92 54 [2] 8c 49 [2] 8e 48 [2] 95 4e [2] 89 49 [2] 95 66 }

  condition:
    any of them
}