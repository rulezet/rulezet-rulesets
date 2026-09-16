rule TTP_XOR_QUAD_CurrentVersionRun_5352 {
  strings:
    $key_5352 = { 00 3d [2] 24 33 [2] 0f 1f [2] 21 3d [2] 35 26 [2] 3a 3c [2] 24 21 [2] 26 20 [2] 3d 26 [2] 21 21 [2] 3d 0e }

  condition:
    any of them
}