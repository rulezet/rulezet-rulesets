rule TTP_XOR_QUAD_CurrentVersionRun_741b {
  strings:
    $key_741b = { 27 74 [2] 03 7a [2] 28 56 [2] 06 74 [2] 12 6f [2] 1d 75 [2] 03 68 [2] 01 69 [2] 1a 6f [2] 06 68 [2] 1a 47 }

  condition:
    any of them
}