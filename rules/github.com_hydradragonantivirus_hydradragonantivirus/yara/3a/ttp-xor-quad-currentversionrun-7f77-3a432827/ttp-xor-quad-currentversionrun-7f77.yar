rule TTP_XOR_QUAD_CurrentVersionRun_7f77 {
  strings:
    $key_7f77 = { 2c 18 [2] 08 16 [2] 23 3a [2] 0d 18 [2] 19 03 [2] 16 19 [2] 08 04 [2] 0a 05 [2] 11 03 [2] 0d 04 [2] 11 2b }

  condition:
    any of them
}