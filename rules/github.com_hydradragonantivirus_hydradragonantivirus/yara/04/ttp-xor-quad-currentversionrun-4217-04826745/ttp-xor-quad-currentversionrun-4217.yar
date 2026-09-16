rule TTP_XOR_QUAD_CurrentVersionRun_4217 {
  strings:
    $key_4217 = { 11 78 [2] 35 76 [2] 1e 5a [2] 30 78 [2] 24 63 [2] 2b 79 [2] 35 64 [2] 37 65 [2] 2c 63 [2] 30 64 [2] 2c 4b }

  condition:
    any of them
}