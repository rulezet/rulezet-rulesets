rule TTP_XOR_QUAD_CurrentVersionRun_4c23 {
  strings:
    $key_4c23 = { 1f 4c [2] 3b 42 [2] 10 6e [2] 3e 4c [2] 2a 57 [2] 25 4d [2] 3b 50 [2] 39 51 [2] 22 57 [2] 3e 50 [2] 22 7f }

  condition:
    any of them
}