rule TTP_XOR_QUAD_CurrentVersionRun_1c23 {
  strings:
    $key_1c23 = { 4f 4c [2] 6b 42 [2] 40 6e [2] 6e 4c [2] 7a 57 [2] 75 4d [2] 6b 50 [2] 69 51 [2] 72 57 [2] 6e 50 [2] 72 7f }

  condition:
    any of them
}