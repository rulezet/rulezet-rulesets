rule TTP_XOR_QUAD_CurrentVersionRun_5309 {
  strings:
    $key_5309 = { 00 66 [2] 24 68 [2] 0f 44 [2] 21 66 [2] 35 7d [2] 3a 67 [2] 24 7a [2] 26 7b [2] 3d 7d [2] 21 7a [2] 3d 55 }

  condition:
    any of them
}