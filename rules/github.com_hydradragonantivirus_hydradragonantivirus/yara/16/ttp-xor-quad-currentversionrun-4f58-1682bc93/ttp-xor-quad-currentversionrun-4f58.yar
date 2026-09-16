rule TTP_XOR_QUAD_CurrentVersionRun_4f58 {
  strings:
    $key_4f58 = { 1c 37 [2] 38 39 [2] 13 15 [2] 3d 37 [2] 29 2c [2] 26 36 [2] 38 2b [2] 3a 2a [2] 21 2c [2] 3d 2b [2] 21 04 }

  condition:
    any of them
}