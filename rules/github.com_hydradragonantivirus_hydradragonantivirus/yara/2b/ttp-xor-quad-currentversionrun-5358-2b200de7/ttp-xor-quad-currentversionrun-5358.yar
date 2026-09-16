rule TTP_XOR_QUAD_CurrentVersionRun_5358 {
  strings:
    $key_5358 = { 00 37 [2] 24 39 [2] 0f 15 [2] 21 37 [2] 35 2c [2] 3a 36 [2] 24 2b [2] 26 2a [2] 3d 2c [2] 21 2b [2] 3d 04 }

  condition:
    any of them
}