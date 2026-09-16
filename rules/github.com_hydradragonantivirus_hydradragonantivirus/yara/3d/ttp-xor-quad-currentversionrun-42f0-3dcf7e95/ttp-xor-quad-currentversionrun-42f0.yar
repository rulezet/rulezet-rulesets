rule TTP_XOR_QUAD_CurrentVersionRun_42f0 {
  strings:
    $key_42f0 = { 11 9f [2] 35 91 [2] 1e bd [2] 30 9f [2] 24 84 [2] 2b 9e [2] 35 83 [2] 37 82 [2] 2c 84 [2] 30 83 [2] 2c ac }

  condition:
    any of them
}