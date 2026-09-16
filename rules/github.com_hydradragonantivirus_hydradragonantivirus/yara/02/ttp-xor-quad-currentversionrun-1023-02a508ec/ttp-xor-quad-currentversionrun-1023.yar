rule TTP_XOR_QUAD_CurrentVersionRun_1023 {
  strings:
    $key_1023 = { 43 4c [2] 67 42 [2] 4c 6e [2] 62 4c [2] 76 57 [2] 79 4d [2] 67 50 [2] 65 51 [2] 7e 57 [2] 62 50 [2] 7e 7f }

  condition:
    any of them
}