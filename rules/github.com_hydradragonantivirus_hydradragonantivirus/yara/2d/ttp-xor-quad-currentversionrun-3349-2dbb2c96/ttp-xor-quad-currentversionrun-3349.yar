rule TTP_XOR_QUAD_CurrentVersionRun_3349 {
  strings:
    $key_3349 = { 60 26 [2] 44 28 [2] 6f 04 [2] 41 26 [2] 55 3d [2] 5a 27 [2] 44 3a [2] 46 3b [2] 5d 3d [2] 41 3a [2] 5d 15 }

  condition:
    any of them
}