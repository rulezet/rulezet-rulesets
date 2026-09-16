rule TTP_XOR_QUAD_CurrentVersionRun_fb5d {
  strings:
    $key_fb5d = { a8 32 [2] 8c 3c [2] a7 10 [2] 89 32 [2] 9d 29 [2] 92 33 [2] 8c 2e [2] 8e 2f [2] 95 29 [2] 89 2e [2] 95 01 }

  condition:
    any of them
}