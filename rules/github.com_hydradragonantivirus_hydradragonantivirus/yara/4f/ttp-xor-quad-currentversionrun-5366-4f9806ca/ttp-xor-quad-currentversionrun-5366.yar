rule TTP_XOR_QUAD_CurrentVersionRun_5366 {
  strings:
    $key_5366 = { 00 09 [2] 24 07 [2] 0f 2b [2] 21 09 [2] 35 12 [2] 3a 08 [2] 24 15 [2] 26 14 [2] 3d 12 [2] 21 15 [2] 3d 3a }

  condition:
    any of them
}