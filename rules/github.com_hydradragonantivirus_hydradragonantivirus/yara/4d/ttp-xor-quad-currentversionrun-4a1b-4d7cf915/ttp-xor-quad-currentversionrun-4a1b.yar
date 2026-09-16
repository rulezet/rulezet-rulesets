rule TTP_XOR_QUAD_CurrentVersionRun_4a1b {
  strings:
    $key_4a1b = { 19 74 [2] 3d 7a [2] 16 56 [2] 38 74 [2] 2c 6f [2] 23 75 [2] 3d 68 [2] 3f 69 [2] 24 6f [2] 38 68 [2] 24 47 }

  condition:
    any of them
}