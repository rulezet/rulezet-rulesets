rule TTP_XOR_QUAD_CurrentVersionRun_5ef4 {
  strings:
    $key_5ef4 = { 0d 9b [2] 29 95 [2] 02 b9 [2] 2c 9b [2] 38 80 [2] 37 9a [2] 29 87 [2] 2b 86 [2] 30 80 [2] 2c 87 [2] 30 a8 }

  condition:
    any of them
}