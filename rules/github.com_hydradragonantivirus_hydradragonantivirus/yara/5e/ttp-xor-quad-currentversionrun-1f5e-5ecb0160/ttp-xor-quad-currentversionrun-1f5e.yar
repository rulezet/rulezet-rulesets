rule TTP_XOR_QUAD_CurrentVersionRun_1f5e {
  strings:
    $key_1f5e = { 4c 31 [2] 68 3f [2] 43 13 [2] 6d 31 [2] 79 2a [2] 76 30 [2] 68 2d [2] 6a 2c [2] 71 2a [2] 6d 2d [2] 71 02 }

  condition:
    any of them
}