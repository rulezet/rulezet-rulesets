rule TTP_XOR_QUAD_CurrentVersionRun_6757 {
  strings:
    $key_6757 = { 34 38 [2] 10 36 [2] 3b 1a [2] 15 38 [2] 01 23 [2] 0e 39 [2] 10 24 [2] 12 25 [2] 09 23 [2] 15 24 [2] 09 0b }

  condition:
    any of them
}