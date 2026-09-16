rule TTP_XOR_QUAD_CurrentVersionRun_fb40 {
  strings:
    $key_fb40 = { a8 2f [2] 8c 21 [2] a7 0d [2] 89 2f [2] 9d 34 [2] 92 2e [2] 8c 33 [2] 8e 32 [2] 95 34 [2] 89 33 [2] 95 1c }

  condition:
    any of them
}