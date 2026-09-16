rule TTP_XOR_QUAD_CurrentVersionRun_fb33 {
  strings:
    $key_fb33 = { a8 5c [2] 8c 52 [2] a7 7e [2] 89 5c [2] 9d 47 [2] 92 5d [2] 8c 40 [2] 8e 41 [2] 95 47 [2] 89 40 [2] 95 6f }

  condition:
    any of them
}