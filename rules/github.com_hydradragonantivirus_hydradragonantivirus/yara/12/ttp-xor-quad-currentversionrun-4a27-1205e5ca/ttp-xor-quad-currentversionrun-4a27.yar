rule TTP_XOR_QUAD_CurrentVersionRun_4a27 {
  strings:
    $key_4a27 = { 19 48 [2] 3d 46 [2] 16 6a [2] 38 48 [2] 2c 53 [2] 23 49 [2] 3d 54 [2] 3f 55 [2] 24 53 [2] 38 54 [2] 24 7b }

  condition:
    any of them
}