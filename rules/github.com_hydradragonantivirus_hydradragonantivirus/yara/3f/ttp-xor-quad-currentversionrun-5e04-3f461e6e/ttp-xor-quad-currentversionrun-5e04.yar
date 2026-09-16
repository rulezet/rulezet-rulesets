rule TTP_XOR_QUAD_CurrentVersionRun_5e04 {
  strings:
    $key_5e04 = { 0d 6b [2] 29 65 [2] 02 49 [2] 2c 6b [2] 38 70 [2] 37 6a [2] 29 77 [2] 2b 76 [2] 30 70 [2] 2c 77 [2] 30 58 }

  condition:
    any of them
}