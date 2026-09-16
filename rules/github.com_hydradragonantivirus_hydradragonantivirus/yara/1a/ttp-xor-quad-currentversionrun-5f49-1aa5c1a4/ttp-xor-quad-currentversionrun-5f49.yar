rule TTP_XOR_QUAD_CurrentVersionRun_5f49 {
  strings:
    $key_5f49 = { 0c 26 [2] 28 28 [2] 03 04 [2] 2d 26 [2] 39 3d [2] 36 27 [2] 28 3a [2] 2a 3b [2] 31 3d [2] 2d 3a [2] 31 15 }

  condition:
    any of them
}