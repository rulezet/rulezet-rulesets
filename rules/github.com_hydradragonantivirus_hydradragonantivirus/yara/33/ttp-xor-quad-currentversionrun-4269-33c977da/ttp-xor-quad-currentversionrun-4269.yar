rule TTP_XOR_QUAD_CurrentVersionRun_4269 {
  strings:
    $key_4269 = { 11 06 [2] 35 08 [2] 1e 24 [2] 30 06 [2] 24 1d [2] 2b 07 [2] 35 1a [2] 37 1b [2] 2c 1d [2] 30 1a [2] 2c 35 }

  condition:
    any of them
}