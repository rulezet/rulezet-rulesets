rule TTP_XOR_QUAD_CurrentVersionRun_422b {
  strings:
    $key_422b = { 11 44 [2] 35 4a [2] 1e 66 [2] 30 44 [2] 24 5f [2] 2b 45 [2] 35 58 [2] 37 59 [2] 2c 5f [2] 30 58 [2] 2c 77 }

  condition:
    any of them
}