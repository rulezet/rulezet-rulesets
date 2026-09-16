rule TTP_XOR_QUAD_CurrentVersionRun_4a4c {
  strings:
    $key_4a4c = { 19 23 [2] 3d 2d [2] 16 01 [2] 38 23 [2] 2c 38 [2] 23 22 [2] 3d 3f [2] 3f 3e [2] 24 38 [2] 38 3f [2] 24 10 }

  condition:
    any of them
}