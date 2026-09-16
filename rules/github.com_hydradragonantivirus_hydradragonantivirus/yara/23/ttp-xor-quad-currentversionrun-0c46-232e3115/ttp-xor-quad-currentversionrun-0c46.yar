rule TTP_XOR_QUAD_CurrentVersionRun_0c46 {
  strings:
    $key_0c46 = { 5f 29 [2] 7b 27 [2] 50 0b [2] 7e 29 [2] 6a 32 [2] 65 28 [2] 7b 35 [2] 79 34 [2] 62 32 [2] 7e 35 [2] 62 1a }

  condition:
    any of them
}