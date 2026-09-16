rule TTP_XOR_QUAD_CurrentVersionRun_5d46 {
  strings:
    $key_5d46 = { 0e 29 [2] 2a 27 [2] 01 0b [2] 2f 29 [2] 3b 32 [2] 34 28 [2] 2a 35 [2] 28 34 [2] 33 32 [2] 2f 35 [2] 33 1a }

  condition:
    any of them
}