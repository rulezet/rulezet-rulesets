rule TTP_XOR_QUAD_CurrentVersionRun_7477 {
  strings:
    $key_7477 = { 27 18 [2] 03 16 [2] 28 3a [2] 06 18 [2] 12 03 [2] 1d 19 [2] 03 04 [2] 01 05 [2] 1a 03 [2] 06 04 [2] 1a 2b }

  condition:
    any of them
}