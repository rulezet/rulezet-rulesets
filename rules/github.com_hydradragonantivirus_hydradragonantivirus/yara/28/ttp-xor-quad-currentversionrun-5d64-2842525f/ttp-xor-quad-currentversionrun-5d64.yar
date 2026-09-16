rule TTP_XOR_QUAD_CurrentVersionRun_5d64 {
  strings:
    $key_5d64 = { 0e 0b [2] 2a 05 [2] 01 29 [2] 2f 0b [2] 3b 10 [2] 34 0a [2] 2a 17 [2] 28 16 [2] 33 10 [2] 2f 17 [2] 33 38 }

  condition:
    any of them
}