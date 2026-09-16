rule TTP_XOR_QUAD_CurrentVersionRun_5376 {
  strings:
    $key_5376 = { 00 19 [2] 24 17 [2] 0f 3b [2] 21 19 [2] 35 02 [2] 3a 18 [2] 24 05 [2] 26 04 [2] 3d 02 [2] 21 05 [2] 3d 2a }

  condition:
    any of them
}