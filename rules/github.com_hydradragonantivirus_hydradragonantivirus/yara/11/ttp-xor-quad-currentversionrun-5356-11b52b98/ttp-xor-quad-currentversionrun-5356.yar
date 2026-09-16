rule TTP_XOR_QUAD_CurrentVersionRun_5356 {
  strings:
    $key_5356 = { 00 39 [2] 24 37 [2] 0f 1b [2] 21 39 [2] 35 22 [2] 3a 38 [2] 24 25 [2] 26 24 [2] 3d 22 [2] 21 25 [2] 3d 0a }

  condition:
    any of them
}