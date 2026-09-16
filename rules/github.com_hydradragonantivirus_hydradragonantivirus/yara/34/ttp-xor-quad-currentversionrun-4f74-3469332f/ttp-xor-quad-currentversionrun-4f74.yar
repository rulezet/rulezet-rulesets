rule TTP_XOR_QUAD_CurrentVersionRun_4f74 {
  strings:
    $key_4f74 = { 1c 1b [2] 38 15 [2] 13 39 [2] 3d 1b [2] 29 00 [2] 26 1a [2] 38 07 [2] 3a 06 [2] 21 00 [2] 3d 07 [2] 21 28 }

  condition:
    any of them
}