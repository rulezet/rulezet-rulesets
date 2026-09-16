rule TTP_XOR_QUAD_CurrentVersionRun_1d23 {
  strings:
    $key_1d23 = { 4e 4c [2] 6a 42 [2] 41 6e [2] 6f 4c [2] 7b 57 [2] 74 4d [2] 6a 50 [2] 68 51 [2] 73 57 [2] 6f 50 [2] 73 7f }

  condition:
    any of them
}