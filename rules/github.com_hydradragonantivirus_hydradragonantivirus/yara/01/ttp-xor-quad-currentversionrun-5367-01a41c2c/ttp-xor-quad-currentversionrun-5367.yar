rule TTP_XOR_QUAD_CurrentVersionRun_5367 {
  strings:
    $key_5367 = { 00 08 [2] 24 06 [2] 0f 2a [2] 21 08 [2] 35 13 [2] 3a 09 [2] 24 14 [2] 26 15 [2] 3d 13 [2] 21 14 [2] 3d 3b }

  condition:
    any of them
}