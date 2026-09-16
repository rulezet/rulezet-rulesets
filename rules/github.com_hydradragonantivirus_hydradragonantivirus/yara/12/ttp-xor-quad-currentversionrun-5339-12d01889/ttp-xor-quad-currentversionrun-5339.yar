rule TTP_XOR_QUAD_CurrentVersionRun_5339 {
  strings:
    $key_5339 = { 00 56 [2] 24 58 [2] 0f 74 [2] 21 56 [2] 35 4d [2] 3a 57 [2] 24 4a [2] 26 4b [2] 3d 4d [2] 21 4a [2] 3d 65 }

  condition:
    any of them
}