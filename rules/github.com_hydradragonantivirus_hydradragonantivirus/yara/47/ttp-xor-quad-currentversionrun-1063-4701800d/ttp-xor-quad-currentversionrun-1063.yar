rule TTP_XOR_QUAD_CurrentVersionRun_1063 {
  strings:
    $key_1063 = { 43 0c [2] 67 02 [2] 4c 2e [2] 62 0c [2] 76 17 [2] 79 0d [2] 67 10 [2] 65 11 [2] 7e 17 [2] 62 10 [2] 7e 3f }

  condition:
    any of them
}