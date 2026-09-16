rule TTP_XOR_QUAD_CurrentVersionRun_2563 {
  strings:
    $key_2563 = { 76 0c [2] 52 02 [2] 79 2e [2] 57 0c [2] 43 17 [2] 4c 0d [2] 52 10 [2] 50 11 [2] 4b 17 [2] 57 10 [2] 4b 3f }

  condition:
    any of them
}