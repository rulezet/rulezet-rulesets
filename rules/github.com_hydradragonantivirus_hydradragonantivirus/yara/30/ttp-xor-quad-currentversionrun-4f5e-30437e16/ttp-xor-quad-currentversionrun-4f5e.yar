rule TTP_XOR_QUAD_CurrentVersionRun_4f5e {
  strings:
    $key_4f5e = { 1c 31 [2] 38 3f [2] 13 13 [2] 3d 31 [2] 29 2a [2] 26 30 [2] 38 2d [2] 3a 2c [2] 21 2a [2] 3d 2d [2] 21 02 }

  condition:
    any of them
}