rule TTP_XOR_QUAD_CurrentVersionRun_4a74 {
  strings:
    $key_4a74 = { 19 1b [2] 3d 15 [2] 16 39 [2] 38 1b [2] 2c 00 [2] 23 1a [2] 3d 07 [2] 3f 06 [2] 24 00 [2] 38 07 [2] 24 28 }

  condition:
    any of them
}