rule TTP_XOR_QUAD_CurrentVersionRun_5369 {
  strings:
    $key_5369 = { 00 06 [2] 24 08 [2] 0f 24 [2] 21 06 [2] 35 1d [2] 3a 07 [2] 24 1a [2] 26 1b [2] 3d 1d [2] 21 1a [2] 3d 35 }

  condition:
    any of them
}