rule TTP_XOR_QUAD_CurrentVersionRun_745b {
  strings:
    $key_745b = { 27 34 [2] 03 3a [2] 28 16 [2] 06 34 [2] 12 2f [2] 1d 35 [2] 03 28 [2] 01 29 [2] 1a 2f [2] 06 28 [2] 1a 07 }

  condition:
    any of them
}