rule TTP_XOR_QUAD_CurrentVersionRun_4a4e {
  strings:
    $key_4a4e = { 19 21 [2] 3d 2f [2] 16 03 [2] 38 21 [2] 2c 3a [2] 23 20 [2] 3d 3d [2] 3f 3c [2] 24 3a [2] 38 3d [2] 24 12 }

  condition:
    any of them
}