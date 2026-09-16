rule TTP_XOR_QUAD_CurrentVersionRun_7459 {
  strings:
    $key_7459 = { 27 36 [2] 03 38 [2] 28 14 [2] 06 36 [2] 12 2d [2] 1d 37 [2] 03 2a [2] 01 2b [2] 1a 2d [2] 06 2a [2] 1a 05 }

  condition:
    any of them
}