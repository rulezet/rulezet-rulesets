rule TTP_XOR_QUAD_CurrentVersionRun_5e47 {
  strings:
    $key_5e47 = { 0d 28 [2] 29 26 [2] 02 0a [2] 2c 28 [2] 38 33 [2] 37 29 [2] 29 34 [2] 2b 35 [2] 30 33 [2] 2c 34 [2] 30 1b }

  condition:
    any of them
}