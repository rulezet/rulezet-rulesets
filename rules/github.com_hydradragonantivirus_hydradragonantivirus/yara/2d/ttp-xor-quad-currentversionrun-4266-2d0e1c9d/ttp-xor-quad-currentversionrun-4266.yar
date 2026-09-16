rule TTP_XOR_QUAD_CurrentVersionRun_4266 {
  strings:
    $key_4266 = { 11 09 [2] 35 07 [2] 1e 2b [2] 30 09 [2] 24 12 [2] 2b 08 [2] 35 15 [2] 37 14 [2] 2c 12 [2] 30 15 [2] 2c 3a }

  condition:
    any of them
}