rule TTP_XOR_QUAD_CurrentVersionRun_5307 {
  strings:
    $key_5307 = { 00 68 [2] 24 66 [2] 0f 4a [2] 21 68 [2] 35 73 [2] 3a 69 [2] 24 74 [2] 26 75 [2] 3d 73 [2] 21 74 [2] 3d 5b }

  condition:
    any of them
}