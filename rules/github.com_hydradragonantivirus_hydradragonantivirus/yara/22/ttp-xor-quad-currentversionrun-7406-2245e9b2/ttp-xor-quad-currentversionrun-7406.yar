rule TTP_XOR_QUAD_CurrentVersionRun_7406 {
  strings:
    $key_7406 = { 27 69 [2] 03 67 [2] 28 4b [2] 06 69 [2] 12 72 [2] 1d 68 [2] 03 75 [2] 01 74 [2] 1a 72 [2] 06 75 [2] 1a 5a }

  condition:
    any of them
}