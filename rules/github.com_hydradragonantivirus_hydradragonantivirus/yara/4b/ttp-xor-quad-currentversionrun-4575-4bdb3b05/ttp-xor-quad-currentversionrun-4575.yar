rule TTP_XOR_QUAD_CurrentVersionRun_4575 {
  strings:
    $key_4575 = { 16 1a [2] 32 14 [2] 19 38 [2] 37 1a [2] 23 01 [2] 2c 1b [2] 32 06 [2] 30 07 [2] 2b 01 [2] 37 06 [2] 2b 29 }

  condition:
    any of them
}