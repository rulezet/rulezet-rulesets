rule TTP_XOR_QUAD_CurrentVersionRun_7469 {
  strings:
    $key_7469 = { 27 06 [2] 03 08 [2] 28 24 [2] 06 06 [2] 12 1d [2] 1d 07 [2] 03 1a [2] 01 1b [2] 1a 1d [2] 06 1a [2] 1a 35 }

  condition:
    any of them
}