rule TTP_XOR_QUAD_CurrentVersionRun_5e25 {
  strings:
    $key_5e25 = { 0d 4a [2] 29 44 [2] 02 68 [2] 2c 4a [2] 38 51 [2] 37 4b [2] 29 56 [2] 2b 57 [2] 30 51 [2] 2c 56 [2] 30 79 }

  condition:
    any of them
}