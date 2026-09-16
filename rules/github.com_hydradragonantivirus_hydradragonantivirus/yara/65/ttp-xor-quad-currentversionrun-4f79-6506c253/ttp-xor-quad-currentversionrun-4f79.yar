rule TTP_XOR_QUAD_CurrentVersionRun_4f79 {
  strings:
    $key_4f79 = { 1c 16 [2] 38 18 [2] 13 34 [2] 3d 16 [2] 29 0d [2] 26 17 [2] 38 0a [2] 3a 0b [2] 21 0d [2] 3d 0a [2] 21 25 }

  condition:
    any of them
}