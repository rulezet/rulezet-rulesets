rule TTP_XOR_QUAD_CurrentVersionRun_5f77 {
  strings:
    $key_5f77 = { 0c 18 [2] 28 16 [2] 03 3a [2] 2d 18 [2] 39 03 [2] 36 19 [2] 28 04 [2] 2a 05 [2] 31 03 [2] 2d 04 [2] 31 2b }

  condition:
    any of them
}