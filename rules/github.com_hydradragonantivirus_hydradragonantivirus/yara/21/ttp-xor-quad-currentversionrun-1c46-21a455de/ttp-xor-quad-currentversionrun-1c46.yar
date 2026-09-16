rule TTP_XOR_QUAD_CurrentVersionRun_1c46 {
  strings:
    $key_1c46 = { 4f 29 [2] 6b 27 [2] 40 0b [2] 6e 29 [2] 7a 32 [2] 75 28 [2] 6b 35 [2] 69 34 [2] 72 32 [2] 6e 35 [2] 72 1a }

  condition:
    any of them
}