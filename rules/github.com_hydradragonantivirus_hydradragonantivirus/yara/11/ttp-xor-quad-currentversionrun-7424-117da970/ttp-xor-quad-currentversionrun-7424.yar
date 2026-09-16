rule TTP_XOR_QUAD_CurrentVersionRun_7424 {
  strings:
    $key_7424 = { 27 4b [2] 03 45 [2] 28 69 [2] 06 4b [2] 12 50 [2] 1d 4a [2] 03 57 [2] 01 56 [2] 1a 50 [2] 06 57 [2] 1a 78 }

  condition:
    any of them
}