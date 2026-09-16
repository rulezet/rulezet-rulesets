rule TTP_XOR_QUAD_CurrentVersionRun_5975 {
  strings:
    $key_5975 = { 0a 1a [2] 2e 14 [2] 05 38 [2] 2b 1a [2] 3f 01 [2] 30 1b [2] 2e 06 [2] 2c 07 [2] 37 01 [2] 2b 06 [2] 37 29 }

  condition:
    any of them
}