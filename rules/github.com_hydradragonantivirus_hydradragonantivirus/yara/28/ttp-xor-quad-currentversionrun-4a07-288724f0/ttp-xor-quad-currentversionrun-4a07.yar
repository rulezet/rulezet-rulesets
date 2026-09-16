rule TTP_XOR_QUAD_CurrentVersionRun_4a07 {
  strings:
    $key_4a07 = { 19 68 [2] 3d 66 [2] 16 4a [2] 38 68 [2] 2c 73 [2] 23 69 [2] 3d 74 [2] 3f 75 [2] 24 73 [2] 38 74 [2] 24 5b }

  condition:
    any of them
}