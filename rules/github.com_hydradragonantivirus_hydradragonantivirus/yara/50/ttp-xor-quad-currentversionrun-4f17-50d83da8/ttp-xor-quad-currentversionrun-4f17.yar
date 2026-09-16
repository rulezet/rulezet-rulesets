rule TTP_XOR_QUAD_CurrentVersionRun_4f17 {
  strings:
    $key_4f17 = { 1c 78 [2] 38 76 [2] 13 5a [2] 3d 78 [2] 29 63 [2] 26 79 [2] 38 64 [2] 3a 65 [2] 21 63 [2] 3d 64 [2] 21 4b }

  condition:
    any of them
}