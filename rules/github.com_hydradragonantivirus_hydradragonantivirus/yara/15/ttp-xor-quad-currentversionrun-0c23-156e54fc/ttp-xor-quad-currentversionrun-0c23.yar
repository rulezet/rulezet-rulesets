rule TTP_XOR_QUAD_CurrentVersionRun_0c23 {
  strings:
    $key_0c23 = { 5f 4c [2] 7b 42 [2] 50 6e [2] 7e 4c [2] 6a 57 [2] 65 4d [2] 7b 50 [2] 79 51 [2] 62 57 [2] 7e 50 [2] 62 7f }

  condition:
    any of them
}