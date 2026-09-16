rule TTP_XOR_QUAD_CurrentVersionRun_044e {
  strings:
    $key_044e = { 57 21 [2] 73 2f [2] 58 03 [2] 76 21 [2] 62 3a [2] 6d 20 [2] 73 3d [2] 71 3c [2] 6a 3a [2] 76 3d [2] 6a 12 }

  condition:
    any of them
}