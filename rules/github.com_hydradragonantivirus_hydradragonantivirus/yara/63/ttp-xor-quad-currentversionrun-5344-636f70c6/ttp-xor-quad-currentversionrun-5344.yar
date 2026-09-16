rule TTP_XOR_QUAD_CurrentVersionRun_5344 {
  strings:
    $key_5344 = { 00 2b [2] 24 25 [2] 0f 09 [2] 21 2b [2] 35 30 [2] 3a 2a [2] 24 37 [2] 26 36 [2] 3d 30 [2] 21 37 [2] 3d 18 }

  condition:
    any of them
}