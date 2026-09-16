rule TTP_XOR_QUAD_CurrentVersionRun_455b {
  strings:
    $key_455b = { 16 34 [2] 32 3a [2] 19 16 [2] 37 34 [2] 23 2f [2] 2c 35 [2] 32 28 [2] 30 29 [2] 2b 2f [2] 37 28 [2] 2b 07 }

  condition:
    any of them
}