rule TTP_XOR_QUAD_CurrentVersionRun_2c46 {
  strings:
    $key_2c46 = { 7f 29 [2] 5b 27 [2] 70 0b [2] 5e 29 [2] 4a 32 [2] 45 28 [2] 5b 35 [2] 59 34 [2] 42 32 [2] 5e 35 [2] 42 1a }

  condition:
    any of them
}