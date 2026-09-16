rule TTP_XOR_QUAD_CurrentVersionRun_6645 {
  strings:
    $key_6645 = { 35 2a [2] 11 24 [2] 3a 08 [2] 14 2a [2] 00 31 [2] 0f 2b [2] 11 36 [2] 13 37 [2] 08 31 [2] 14 36 [2] 08 19 }

  condition:
    any of them
}