rule TTP_XOR_QUAD_CurrentVersionRun_714e {
  strings:
    $key_714e = { 22 21 [2] 06 2f [2] 2d 03 [2] 03 21 [2] 17 3a [2] 18 20 [2] 06 3d [2] 04 3c [2] 1f 3a [2] 03 3d [2] 1f 12 }

  condition:
    any of them
}