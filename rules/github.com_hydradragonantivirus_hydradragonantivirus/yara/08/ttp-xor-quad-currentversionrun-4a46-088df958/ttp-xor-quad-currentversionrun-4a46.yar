rule TTP_XOR_QUAD_CurrentVersionRun_4a46 {
  strings:
    $key_4a46 = { 19 29 [2] 3d 27 [2] 16 0b [2] 38 29 [2] 2c 32 [2] 23 28 [2] 3d 35 [2] 3f 34 [2] 24 32 [2] 38 35 [2] 24 1a }

  condition:
    any of them
}