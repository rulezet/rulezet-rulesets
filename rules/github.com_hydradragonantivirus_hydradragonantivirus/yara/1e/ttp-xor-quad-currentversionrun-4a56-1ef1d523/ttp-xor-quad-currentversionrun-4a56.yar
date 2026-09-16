rule TTP_XOR_QUAD_CurrentVersionRun_4a56 {
  strings:
    $key_4a56 = { 19 39 [2] 3d 37 [2] 16 1b [2] 38 39 [2] 2c 22 [2] 23 38 [2] 3d 25 [2] 3f 24 [2] 24 22 [2] 38 25 [2] 24 0a }

  condition:
    any of them
}