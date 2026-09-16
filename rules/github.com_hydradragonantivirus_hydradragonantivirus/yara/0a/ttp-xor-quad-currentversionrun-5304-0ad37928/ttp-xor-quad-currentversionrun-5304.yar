rule TTP_XOR_QUAD_CurrentVersionRun_5304 {
  strings:
    $key_5304 = { 00 6b [2] 24 65 [2] 0f 49 [2] 21 6b [2] 35 70 [2] 3a 6a [2] 24 77 [2] 26 76 [2] 3d 70 [2] 21 77 [2] 3d 58 }

  condition:
    any of them
}