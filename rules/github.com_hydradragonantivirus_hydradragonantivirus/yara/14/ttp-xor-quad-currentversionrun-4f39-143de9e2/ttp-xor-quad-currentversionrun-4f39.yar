rule TTP_XOR_QUAD_CurrentVersionRun_4f39 {
  strings:
    $key_4f39 = { 1c 56 [2] 38 58 [2] 13 74 [2] 3d 56 [2] 29 4d [2] 26 57 [2] 38 4a [2] 3a 4b [2] 21 4d [2] 3d 4a [2] 21 65 }

  condition:
    any of them
}