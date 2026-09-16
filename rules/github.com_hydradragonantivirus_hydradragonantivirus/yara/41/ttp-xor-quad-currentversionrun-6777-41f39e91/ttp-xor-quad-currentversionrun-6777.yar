rule TTP_XOR_QUAD_CurrentVersionRun_6777 {
  strings:
    $key_6777 = { 34 18 [2] 10 16 [2] 3b 3a [2] 15 18 [2] 01 03 [2] 0e 19 [2] 10 04 [2] 12 05 [2] 09 03 [2] 15 04 [2] 09 2b }

  condition:
    any of them
}