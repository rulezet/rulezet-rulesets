rule TTP_XOR_QUAD_CurrentVersionRun_5375 {
  strings:
    $key_5375 = { 00 1a [2] 24 14 [2] 0f 38 [2] 21 1a [2] 35 01 [2] 3a 1b [2] 24 06 [2] 26 07 [2] 3d 01 [2] 21 06 [2] 3d 29 }

  condition:
    any of them
}