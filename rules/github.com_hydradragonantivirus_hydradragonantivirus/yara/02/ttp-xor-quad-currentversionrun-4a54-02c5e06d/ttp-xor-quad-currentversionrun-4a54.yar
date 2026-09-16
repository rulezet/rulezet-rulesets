rule TTP_XOR_QUAD_CurrentVersionRun_4a54 {
  strings:
    $key_4a54 = { 19 3b [2] 3d 35 [2] 16 19 [2] 38 3b [2] 2c 20 [2] 23 3a [2] 3d 27 [2] 3f 26 [2] 24 20 [2] 38 27 [2] 24 08 }

  condition:
    any of them
}