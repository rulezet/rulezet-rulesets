rule TTP_XOR_QUAD_CurrentVersionRun_fb22 {
  strings:
    $key_fb22 = { a8 4d [2] 8c 43 [2] a7 6f [2] 89 4d [2] 9d 56 [2] 92 4c [2] 8c 51 [2] 8e 50 [2] 95 56 [2] 89 51 [2] 95 7e }

  condition:
    any of them
}