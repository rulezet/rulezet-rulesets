rule TTP_XOR_QUAD_CurrentVersionRun_4564 {
  strings:
    $key_4564 = { 16 0b [2] 32 05 [2] 19 29 [2] 37 0b [2] 23 10 [2] 2c 0a [2] 32 17 [2] 30 16 [2] 2b 10 [2] 37 17 [2] 2b 38 }

  condition:
    any of them
}