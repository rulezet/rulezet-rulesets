rule TTP_XOR_QUAD_CurrentVersionRun_fb1c {
  strings:
    $key_fb1c = { a8 73 [2] 8c 7d [2] a7 51 [2] 89 73 [2] 9d 68 [2] 92 72 [2] 8c 6f [2] 8e 6e [2] 95 68 [2] 89 6f [2] 95 40 }

  condition:
    any of them
}