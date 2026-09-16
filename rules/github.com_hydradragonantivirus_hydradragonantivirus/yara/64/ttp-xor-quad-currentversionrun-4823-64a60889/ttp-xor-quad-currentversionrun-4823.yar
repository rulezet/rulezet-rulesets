rule TTP_XOR_QUAD_CurrentVersionRun_4823 {
  strings:
    $key_4823 = { 1b 4c [2] 3f 42 [2] 14 6e [2] 3a 4c [2] 2e 57 [2] 21 4d [2] 3f 50 [2] 3d 51 [2] 26 57 [2] 3a 50 [2] 26 7f }

  condition:
    any of them
}