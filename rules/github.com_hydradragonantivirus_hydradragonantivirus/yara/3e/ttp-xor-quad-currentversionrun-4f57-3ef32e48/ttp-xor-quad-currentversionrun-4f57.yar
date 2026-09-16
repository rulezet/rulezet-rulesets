rule TTP_XOR_QUAD_CurrentVersionRun_4f57 {
  strings:
    $key_4f57 = { 1c 38 [2] 38 36 [2] 13 1a [2] 3d 38 [2] 29 23 [2] 26 39 [2] 38 24 [2] 3a 25 [2] 21 23 [2] 3d 24 [2] 21 0b }

  condition:
    any of them
}