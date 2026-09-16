rule TTP_XOR_QUAD_CurrentVersionRun_595b {
  strings:
    $key_595b = { 0a 34 [2] 2e 3a [2] 05 16 [2] 2b 34 [2] 3f 2f [2] 30 35 [2] 2e 28 [2] 2c 29 [2] 37 2f [2] 2b 28 [2] 37 07 }

  condition:
    any of them
}