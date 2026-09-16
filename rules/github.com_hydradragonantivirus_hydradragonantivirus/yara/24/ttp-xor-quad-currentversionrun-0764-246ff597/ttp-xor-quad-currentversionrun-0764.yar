rule TTP_XOR_QUAD_CurrentVersionRun_0764 {
  strings:
    $key_0764 = { 54 0b [2] 70 05 [2] 5b 29 [2] 75 0b [2] 61 10 [2] 6e 0a [2] 70 17 [2] 72 16 [2] 69 10 [2] 75 17 [2] 69 38 }

  condition:
    any of them
}