rule TTP_XOR_QUAD_CurrentVersionRun_3174 {
  strings:
    $key_3174 = { 62 1b [2] 46 15 [2] 6d 39 [2] 43 1b [2] 57 00 [2] 58 1a [2] 46 07 [2] 44 06 [2] 5f 00 [2] 43 07 [2] 5f 28 }

  condition:
    any of them
}