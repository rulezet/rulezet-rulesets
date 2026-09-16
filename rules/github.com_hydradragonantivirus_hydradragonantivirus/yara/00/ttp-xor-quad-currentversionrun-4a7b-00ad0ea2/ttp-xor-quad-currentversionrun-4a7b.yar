rule TTP_XOR_QUAD_CurrentVersionRun_4a7b {
  strings:
    $key_4a7b = { 19 14 [2] 3d 1a [2] 16 36 [2] 38 14 [2] 2c 0f [2] 23 15 [2] 3d 08 [2] 3f 09 [2] 24 0f [2] 38 08 [2] 24 27 }

  condition:
    any of them
}