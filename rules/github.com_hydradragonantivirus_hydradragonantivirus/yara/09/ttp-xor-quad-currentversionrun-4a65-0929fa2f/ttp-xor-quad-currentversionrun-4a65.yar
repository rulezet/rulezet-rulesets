rule TTP_XOR_QUAD_CurrentVersionRun_4a65 {
  strings:
    $key_4a65 = { 19 0a [2] 3d 04 [2] 16 28 [2] 38 0a [2] 2c 11 [2] 23 0b [2] 3d 16 [2] 3f 17 [2] 24 11 [2] 38 16 [2] 24 39 }

  condition:
    any of them
}