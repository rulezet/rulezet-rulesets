rule TTP_XOR_QUAD_CurrentVersionRun_2a4e {
  strings:
    $key_2a4e = { 79 21 [2] 5d 2f [2] 76 03 [2] 58 21 [2] 4c 3a [2] 43 20 [2] 5d 3d [2] 5f 3c [2] 44 3a [2] 58 3d [2] 44 12 }

  condition:
    any of them
}