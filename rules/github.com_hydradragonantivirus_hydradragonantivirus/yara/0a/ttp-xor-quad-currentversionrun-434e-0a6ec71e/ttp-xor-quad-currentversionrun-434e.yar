rule TTP_XOR_QUAD_CurrentVersionRun_434e {
  strings:
    $key_434e = { 10 21 [2] 34 2f [2] 1f 03 [2] 31 21 [2] 25 3a [2] 2a 20 [2] 34 3d [2] 36 3c [2] 2d 3a [2] 31 3d [2] 2d 12 }

  condition:
    any of them
}