rule TTP_XOR_QUAD_CurrentVersionRun_5f4e {
  strings:
    $key_5f4e = { 0c 21 [2] 28 2f [2] 03 03 [2] 2d 21 [2] 39 3a [2] 36 20 [2] 28 3d [2] 2a 3c [2] 31 3a [2] 2d 3d [2] 31 12 }

  condition:
    any of them
}