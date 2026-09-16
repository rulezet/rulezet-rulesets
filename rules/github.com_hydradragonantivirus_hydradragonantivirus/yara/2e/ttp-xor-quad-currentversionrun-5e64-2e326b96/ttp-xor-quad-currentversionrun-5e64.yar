rule TTP_XOR_QUAD_CurrentVersionRun_5e64 {
  strings:
    $key_5e64 = { 0d 0b [2] 29 05 [2] 02 29 [2] 2c 0b [2] 38 10 [2] 37 0a [2] 29 17 [2] 2b 16 [2] 30 10 [2] 2c 17 [2] 30 38 }

  condition:
    any of them
}