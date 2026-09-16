rule TTP_XOR_QUAD_CurrentVersionRun_2d4e {
  strings:
    $key_2d4e = { 7e 21 [2] 5a 2f [2] 71 03 [2] 5f 21 [2] 4b 3a [2] 44 20 [2] 5a 3d [2] 58 3c [2] 43 3a [2] 5f 3d [2] 43 12 }

  condition:
    any of them
}