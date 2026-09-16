rule TTP_XOR_QUAD_CurrentVersionRun_7f49 {
  strings:
    $key_7f49 = { 2c 26 [2] 08 28 [2] 23 04 [2] 0d 26 [2] 19 3d [2] 16 27 [2] 08 3a [2] 0a 3b [2] 11 3d [2] 0d 3a [2] 11 15 }

  condition:
    any of them
}