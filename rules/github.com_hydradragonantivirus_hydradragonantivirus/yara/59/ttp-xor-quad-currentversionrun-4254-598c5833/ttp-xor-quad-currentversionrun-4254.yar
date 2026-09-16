rule TTP_XOR_QUAD_CurrentVersionRun_4254 {
  strings:
    $key_4254 = { 11 3b [2] 35 35 [2] 1e 19 [2] 30 3b [2] 24 20 [2] 2b 3a [2] 35 27 [2] 37 26 [2] 2c 20 [2] 30 27 [2] 2c 08 }

  condition:
    any of them
}