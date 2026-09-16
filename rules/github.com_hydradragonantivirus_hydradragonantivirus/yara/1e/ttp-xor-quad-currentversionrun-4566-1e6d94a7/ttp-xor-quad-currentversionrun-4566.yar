rule TTP_XOR_QUAD_CurrentVersionRun_4566 {
  strings:
    $key_4566 = { 16 09 [2] 32 07 [2] 19 2b [2] 37 09 [2] 23 12 [2] 2c 08 [2] 32 15 [2] 30 14 [2] 2b 12 [2] 37 15 [2] 2b 3a }

  condition:
    any of them
}