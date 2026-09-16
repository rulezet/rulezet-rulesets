rule TTP_XOR_QUAD_CurrentVersionRun_5347 {
  strings:
    $key_5347 = { 00 28 [2] 24 26 [2] 0f 0a [2] 21 28 [2] 35 33 [2] 3a 29 [2] 24 34 [2] 26 35 [2] 3d 33 [2] 21 34 [2] 3d 1b }

  condition:
    any of them
}