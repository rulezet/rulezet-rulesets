rule TTP_XOR_QUAD_CurrentVersionRun_5e75 {
  strings:
    $key_5e75 = { 0d 1a [2] 29 14 [2] 02 38 [2] 2c 1a [2] 38 01 [2] 37 1b [2] 29 06 [2] 2b 07 [2] 30 01 [2] 2c 06 [2] 30 29 }

  condition:
    any of them
}