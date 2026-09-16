rule TTP_XOR_QUAD_CurrentVersionRun_fb72 {
  strings:
    $key_fb72 = { a8 1d [2] 8c 13 [2] a7 3f [2] 89 1d [2] 9d 06 [2] 92 1c [2] 8c 01 [2] 8e 00 [2] 95 06 [2] 89 01 [2] 95 2e }

  condition:
    any of them
}