rule TTP_XOR_QUAD_CurrentVersionRun_fb2d {
  strings:
    $key_fb2d = { a8 42 [2] 8c 4c [2] a7 60 [2] 89 42 [2] 9d 59 [2] 92 43 [2] 8c 5e [2] 8e 5f [2] 95 59 [2] 89 5e [2] 95 71 }

  condition:
    any of them
}