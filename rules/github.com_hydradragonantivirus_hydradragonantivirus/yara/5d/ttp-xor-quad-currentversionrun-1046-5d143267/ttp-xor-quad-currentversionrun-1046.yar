rule TTP_XOR_QUAD_CurrentVersionRun_1046 {
  strings:
    $key_1046 = { 43 29 [2] 67 27 [2] 4c 0b [2] 62 29 [2] 76 32 [2] 79 28 [2] 67 35 [2] 65 34 [2] 7e 32 [2] 62 35 [2] 7e 1a }

  condition:
    any of them
}