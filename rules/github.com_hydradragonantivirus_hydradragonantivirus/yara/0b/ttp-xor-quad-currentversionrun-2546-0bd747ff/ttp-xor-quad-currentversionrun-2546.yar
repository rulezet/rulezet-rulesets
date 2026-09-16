rule TTP_XOR_QUAD_CurrentVersionRun_2546 {
  strings:
    $key_2546 = { 76 29 [2] 52 27 [2] 79 0b [2] 57 29 [2] 43 32 [2] 4c 28 [2] 52 35 [2] 50 34 [2] 4b 32 [2] 57 35 [2] 4b 1a }

  condition:
    any of them
}