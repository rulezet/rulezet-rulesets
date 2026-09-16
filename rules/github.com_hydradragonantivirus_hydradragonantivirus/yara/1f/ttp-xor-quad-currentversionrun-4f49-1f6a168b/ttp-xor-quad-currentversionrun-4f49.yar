rule TTP_XOR_QUAD_CurrentVersionRun_4f49 {
  strings:
    $key_4f49 = { 1c 26 [2] 38 28 [2] 13 04 [2] 3d 26 [2] 29 3d [2] 26 27 [2] 38 3a [2] 3a 3b [2] 21 3d [2] 3d 3a [2] 21 15 }

  condition:
    any of them
}