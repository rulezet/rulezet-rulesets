rule TTP_XOR_QUAD_CurrentVersionRun_5946 {
  strings:
    $key_5946 = { 0a 29 [2] 2e 27 [2] 05 0b [2] 2b 29 [2] 3f 32 [2] 30 28 [2] 2e 35 [2] 2c 34 [2] 37 32 [2] 2b 35 [2] 37 1a }

  condition:
    any of them
}