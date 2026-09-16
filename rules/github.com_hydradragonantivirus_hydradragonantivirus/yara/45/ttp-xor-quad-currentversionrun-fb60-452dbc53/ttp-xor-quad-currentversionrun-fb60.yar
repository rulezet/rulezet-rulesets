rule TTP_XOR_QUAD_CurrentVersionRun_fb60 {
  strings:
    $key_fb60 = { a8 0f [2] 8c 01 [2] a7 2d [2] 89 0f [2] 9d 14 [2] 92 0e [2] 8c 13 [2] 8e 12 [2] 95 14 [2] 89 13 [2] 95 3c }

  condition:
    any of them
}