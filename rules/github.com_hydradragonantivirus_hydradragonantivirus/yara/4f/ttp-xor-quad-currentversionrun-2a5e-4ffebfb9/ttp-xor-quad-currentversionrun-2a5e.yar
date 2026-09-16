rule TTP_XOR_QUAD_CurrentVersionRun_2a5e {
  strings:
    $key_2a5e = { 79 31 [2] 5d 3f [2] 76 13 [2] 58 31 [2] 4c 2a [2] 43 30 [2] 5d 2d [2] 5f 2c [2] 44 2a [2] 58 2d [2] 44 02 }

  condition:
    any of them
}