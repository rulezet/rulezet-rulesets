rule TTP_XOR_QUAD_CurrentVersionRun_5e27 {
  strings:
    $key_5e27 = { 0d 48 [2] 29 46 [2] 02 6a [2] 2c 48 [2] 38 53 [2] 37 49 [2] 29 54 [2] 2b 55 [2] 30 53 [2] 2c 54 [2] 30 7b }

  condition:
    any of them
}