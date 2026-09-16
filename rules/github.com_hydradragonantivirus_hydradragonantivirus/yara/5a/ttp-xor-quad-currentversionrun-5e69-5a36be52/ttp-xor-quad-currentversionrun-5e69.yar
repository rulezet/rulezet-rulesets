rule TTP_XOR_QUAD_CurrentVersionRun_5e69 {
  strings:
    $key_5e69 = { 0d 06 [2] 29 08 [2] 02 24 [2] 2c 06 [2] 38 1d [2] 37 07 [2] 29 1a [2] 2b 1b [2] 30 1d [2] 2c 1a [2] 30 35 }

  condition:
    any of them
}