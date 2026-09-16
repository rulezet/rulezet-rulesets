rule TTP_XOR_QUAD_CurrentVersionRun_7c46 {
  strings:
    $key_7c46 = { 2f 29 [2] 0b 27 [2] 20 0b [2] 0e 29 [2] 1a 32 [2] 15 28 [2] 0b 35 [2] 09 34 [2] 12 32 [2] 0e 35 [2] 12 1a }

  condition:
    any of them
}