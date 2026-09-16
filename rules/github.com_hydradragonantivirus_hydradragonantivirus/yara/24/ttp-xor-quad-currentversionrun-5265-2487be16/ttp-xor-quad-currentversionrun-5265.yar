rule TTP_XOR_QUAD_CurrentVersionRun_5265 {
  strings:
    $key_5265 = { 01 0a [2] 25 04 [2] 0e 28 [2] 20 0a [2] 34 11 [2] 3b 0b [2] 25 16 [2] 27 17 [2] 3c 11 [2] 20 16 [2] 3c 39 }

  condition:
    any of them
}