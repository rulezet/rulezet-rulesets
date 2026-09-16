rule TTP_XOR_QUAD_CurrentVersionRun_42f4 {
  strings:
    $key_42f4 = { 11 9b [2] 35 95 [2] 1e b9 [2] 30 9b [2] 24 80 [2] 2b 9a [2] 35 87 [2] 37 86 [2] 2c 80 [2] 30 87 [2] 2c a8 }

  condition:
    any of them
}