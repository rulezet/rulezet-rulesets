rule TTP_XOR_QUAD_CurrentVersionRun_6477 {
  strings:
    $key_6477 = { 37 18 [2] 13 16 [2] 38 3a [2] 16 18 [2] 02 03 [2] 0d 19 [2] 13 04 [2] 11 05 [2] 0a 03 [2] 16 04 [2] 0a 2b }

  condition:
    any of them
}