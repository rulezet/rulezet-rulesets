rule TTP_XOR_QUAD_CurrentVersionRun_fb50 {
  strings:
    $key_fb50 = { a8 3f [2] 8c 31 [2] a7 1d [2] 89 3f [2] 9d 24 [2] 92 3e [2] 8c 23 [2] 8e 22 [2] 95 24 [2] 89 23 [2] 95 0c }

  condition:
    any of them
}