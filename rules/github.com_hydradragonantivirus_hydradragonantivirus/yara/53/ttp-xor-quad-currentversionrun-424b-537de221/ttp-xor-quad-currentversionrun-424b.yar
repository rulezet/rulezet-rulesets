rule TTP_XOR_QUAD_CurrentVersionRun_424b {
  strings:
    $key_424b = { 11 24 [2] 35 2a [2] 1e 06 [2] 30 24 [2] 24 3f [2] 2b 25 [2] 35 38 [2] 37 39 [2] 2c 3f [2] 30 38 [2] 2c 17 }

  condition:
    any of them
}