rule TTP_XOR_QUAD_CurrentVersionRun_2d23 {
  strings:
    $key_2d23 = { 7e 4c [2] 5a 42 [2] 71 6e [2] 5f 4c [2] 4b 57 [2] 44 4d [2] 5a 50 [2] 58 51 [2] 43 57 [2] 5f 50 [2] 43 7f }

  condition:
    any of them
}