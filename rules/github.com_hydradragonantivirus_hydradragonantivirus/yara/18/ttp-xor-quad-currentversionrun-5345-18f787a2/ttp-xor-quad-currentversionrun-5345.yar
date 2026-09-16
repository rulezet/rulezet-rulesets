rule TTP_XOR_QUAD_CurrentVersionRun_5345 {
  strings:
    $key_5345 = { 00 2a [2] 24 24 [2] 0f 08 [2] 21 2a [2] 35 31 [2] 3a 2b [2] 24 36 [2] 26 37 [2] 3d 31 [2] 21 36 [2] 3d 19 }

  condition:
    any of them
}