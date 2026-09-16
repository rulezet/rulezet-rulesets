rule TTP_XOR_QUAD_CurrentVersionRun_5e5b {
  strings:
    $key_5e5b = { 0d 34 [2] 29 3a [2] 02 16 [2] 2c 34 [2] 38 2f [2] 37 35 [2] 29 28 [2] 2b 29 [2] 30 2f [2] 2c 28 [2] 30 07 }

  condition:
    any of them
}