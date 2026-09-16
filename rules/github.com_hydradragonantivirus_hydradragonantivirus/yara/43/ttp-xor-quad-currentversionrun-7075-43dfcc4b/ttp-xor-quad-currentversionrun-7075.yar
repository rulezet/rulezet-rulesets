rule TTP_XOR_QUAD_CurrentVersionRun_7075 {
  strings:
    $key_7075 = { 23 1a [2] 07 14 [2] 2c 38 [2] 02 1a [2] 16 01 [2] 19 1b [2] 07 06 [2] 05 07 [2] 1e 01 [2] 02 06 [2] 1e 29 }

  condition:
    any of them
}