rule TTP_XOR_QUAD_CurrentVersionRun_1923 {
  strings:
    $key_1923 = { 4a 4c [2] 6e 42 [2] 45 6e [2] 6b 4c [2] 7f 57 [2] 70 4d [2] 6e 50 [2] 6c 51 [2] 77 57 [2] 6b 50 [2] 77 7f }

  condition:
    any of them
}