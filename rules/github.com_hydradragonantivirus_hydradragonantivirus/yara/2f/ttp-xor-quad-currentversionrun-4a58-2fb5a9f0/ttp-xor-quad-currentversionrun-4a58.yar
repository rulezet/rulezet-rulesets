rule TTP_XOR_QUAD_CurrentVersionRun_4a58 {
  strings:
    $key_4a58 = { 19 37 [2] 3d 39 [2] 16 15 [2] 38 37 [2] 2c 2c [2] 23 36 [2] 3d 2b [2] 3f 2a [2] 24 2c [2] 38 2b [2] 24 04 }

  condition:
    any of them
}