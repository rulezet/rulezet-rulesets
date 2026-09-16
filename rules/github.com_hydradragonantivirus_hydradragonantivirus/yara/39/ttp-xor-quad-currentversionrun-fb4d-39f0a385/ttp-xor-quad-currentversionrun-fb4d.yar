rule TTP_XOR_QUAD_CurrentVersionRun_fb4d {
  strings:
    $key_fb4d = { a8 22 [2] 8c 2c [2] a7 00 [2] 89 22 [2] 9d 39 [2] 92 23 [2] 8c 3e [2] 8e 3f [2] 95 39 [2] 89 3e [2] 95 11 }

  condition:
    any of them
}