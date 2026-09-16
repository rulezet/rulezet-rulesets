rule TTP_XOR_QUAD_CurrentVersionRun_4f5f {
  strings:
    $key_4f5f = { 1c 30 [2] 38 3e [2] 13 12 [2] 3d 30 [2] 29 2b [2] 26 31 [2] 38 2c [2] 3a 2d [2] 21 2b [2] 3d 2c [2] 21 03 }

  condition:
    any of them
}