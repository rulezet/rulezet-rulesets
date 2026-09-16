rule TTP_XOR_QUAD_CurrentVersionRun_7375 {
  strings:
    $key_7375 = { 20 1a [2] 04 14 [2] 2f 38 [2] 01 1a [2] 15 01 [2] 1a 1b [2] 04 06 [2] 06 07 [2] 1d 01 [2] 01 06 [2] 1d 29 }

  condition:
    any of them
}