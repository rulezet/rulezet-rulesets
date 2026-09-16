rule TTP_XOR_QUAD_CurrentVersionRun_fb62 {
  strings:
    $key_fb62 = { a8 0d [2] 8c 03 [2] a7 2f [2] 89 0d [2] 9d 16 [2] 92 0c [2] 8c 11 [2] 8e 10 [2] 95 16 [2] 89 11 [2] 95 3e }

  condition:
    any of them
}