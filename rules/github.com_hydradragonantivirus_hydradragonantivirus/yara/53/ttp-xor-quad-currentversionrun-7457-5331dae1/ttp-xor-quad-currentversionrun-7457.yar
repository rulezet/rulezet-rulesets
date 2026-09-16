rule TTP_XOR_QUAD_CurrentVersionRun_7457 {
  strings:
    $key_7457 = { 27 38 [2] 03 36 [2] 28 1a [2] 06 38 [2] 12 23 [2] 1d 39 [2] 03 24 [2] 01 25 [2] 1a 23 [2] 06 24 [2] 1a 0b }

  condition:
    any of them
}