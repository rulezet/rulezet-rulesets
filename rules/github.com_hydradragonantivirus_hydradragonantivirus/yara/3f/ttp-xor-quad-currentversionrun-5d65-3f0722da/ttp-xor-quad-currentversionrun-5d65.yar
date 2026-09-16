rule TTP_XOR_QUAD_CurrentVersionRun_5d65 {
  strings:
    $key_5d65 = { 0e 0a [2] 2a 04 [2] 01 28 [2] 2f 0a [2] 3b 11 [2] 34 0b [2] 2a 16 [2] 28 17 [2] 33 11 [2] 2f 16 [2] 33 39 }

  condition:
    any of them
}