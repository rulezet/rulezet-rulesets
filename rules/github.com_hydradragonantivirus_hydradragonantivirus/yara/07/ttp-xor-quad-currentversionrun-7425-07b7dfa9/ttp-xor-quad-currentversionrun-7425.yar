rule TTP_XOR_QUAD_CurrentVersionRun_7425 {
  strings:
    $key_7425 = { 27 4a [2] 03 44 [2] 28 68 [2] 06 4a [2] 12 51 [2] 1d 4b [2] 03 56 [2] 01 57 [2] 1a 51 [2] 06 56 [2] 1a 79 }

  condition:
    any of them
}