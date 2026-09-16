rule TTP_XOR_QUAD_CurrentVersionRun_5a49 {
  strings:
    $key_5a49 = { 09 26 [2] 2d 28 [2] 06 04 [2] 28 26 [2] 3c 3d [2] 33 27 [2] 2d 3a [2] 2f 3b [2] 34 3d [2] 28 3a [2] 34 15 }

  condition:
    any of them
}