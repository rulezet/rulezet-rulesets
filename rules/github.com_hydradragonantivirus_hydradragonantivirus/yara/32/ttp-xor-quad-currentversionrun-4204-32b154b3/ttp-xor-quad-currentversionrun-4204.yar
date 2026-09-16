rule TTP_XOR_QUAD_CurrentVersionRun_4204 {
  strings:
    $key_4204 = { 11 6b [2] 35 65 [2] 1e 49 [2] 30 6b [2] 24 70 [2] 2b 6a [2] 35 77 [2] 37 76 [2] 2c 70 [2] 30 77 [2] 2c 58 }

  condition:
    any of them
}