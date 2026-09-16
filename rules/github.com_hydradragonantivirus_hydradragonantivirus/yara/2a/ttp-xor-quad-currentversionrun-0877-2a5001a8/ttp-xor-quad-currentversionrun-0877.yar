rule TTP_XOR_QUAD_CurrentVersionRun_0877 {
  strings:
    $key_0877 = { 5b 18 [2] 7f 16 [2] 54 3a [2] 7a 18 [2] 6e 03 [2] 61 19 [2] 7f 04 [2] 7d 05 [2] 66 03 [2] 7a 04 [2] 66 2b }

  condition:
    any of them
}