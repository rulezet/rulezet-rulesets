rule TTP_XOR_QUAD_CurrentVersionRun_fb0c {
  strings:
    $key_fb0c = { a8 63 [2] 8c 6d [2] a7 41 [2] 89 63 [2] 9d 78 [2] 92 62 [2] 8c 7f [2] 8e 7e [2] 95 78 [2] 89 7f [2] 95 50 }

  condition:
    any of them
}