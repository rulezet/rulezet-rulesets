rule TTP_XOR_QUAD_CurrentVersionRun_7476 {
  strings:
    $key_7476 = { 27 19 [2] 03 17 [2] 28 3b [2] 06 19 [2] 12 02 [2] 1d 18 [2] 03 05 [2] 01 04 [2] 1a 02 [2] 06 05 [2] 1a 2a }

  condition:
    any of them
}