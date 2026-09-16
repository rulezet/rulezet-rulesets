rule TTP_XOR_QUAD_CurrentVersionRun_5359 {
  strings:
    $key_5359 = { 00 36 [2] 24 38 [2] 0f 14 [2] 21 36 [2] 35 2d [2] 3a 37 [2] 24 2a [2] 26 2b [2] 3d 2d [2] 21 2a [2] 3d 05 }

  condition:
    any of them
}