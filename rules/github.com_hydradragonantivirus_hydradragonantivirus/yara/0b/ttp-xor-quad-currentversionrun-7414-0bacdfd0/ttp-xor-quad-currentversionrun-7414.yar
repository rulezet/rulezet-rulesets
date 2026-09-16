rule TTP_XOR_QUAD_CurrentVersionRun_7414 {
  strings:
    $key_7414 = { 27 7b [2] 03 75 [2] 28 59 [2] 06 7b [2] 12 60 [2] 1d 7a [2] 03 67 [2] 01 66 [2] 1a 60 [2] 06 67 [2] 1a 48 }

  condition:
    any of them
}