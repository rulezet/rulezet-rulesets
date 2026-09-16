rule TTP_XOR_QUAD_CurrentVersionRun_4f59 {
  strings:
    $key_4f59 = { 1c 36 [2] 38 38 [2] 13 14 [2] 3d 36 [2] 29 2d [2] 26 37 [2] 38 2a [2] 3a 2b [2] 21 2d [2] 3d 2a [2] 21 05 }

  condition:
    any of them
}