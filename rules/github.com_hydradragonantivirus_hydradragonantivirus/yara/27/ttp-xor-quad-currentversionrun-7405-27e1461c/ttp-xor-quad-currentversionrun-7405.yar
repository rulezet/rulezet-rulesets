rule TTP_XOR_QUAD_CurrentVersionRun_7405 {
  strings:
    $key_7405 = { 27 6a [2] 03 64 [2] 28 48 [2] 06 6a [2] 12 71 [2] 1d 6b [2] 03 76 [2] 01 77 [2] 1a 71 [2] 06 76 [2] 1a 59 }

  condition:
    any of them
}