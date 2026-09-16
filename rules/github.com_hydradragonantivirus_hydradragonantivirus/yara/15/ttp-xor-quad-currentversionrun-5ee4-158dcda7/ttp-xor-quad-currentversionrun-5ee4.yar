rule TTP_XOR_QUAD_CurrentVersionRun_5ee4 {
  strings:
    $key_5ee4 = { 0d 8b [2] 29 85 [2] 02 a9 [2] 2c 8b [2] 38 90 [2] 37 8a [2] 29 97 [2] 2b 96 [2] 30 90 [2] 2c 97 [2] 30 b8 }

  condition:
    any of them
}