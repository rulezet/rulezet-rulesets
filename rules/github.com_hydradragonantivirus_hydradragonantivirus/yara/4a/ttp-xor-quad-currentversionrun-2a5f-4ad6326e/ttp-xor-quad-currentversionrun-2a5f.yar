rule TTP_XOR_QUAD_CurrentVersionRun_2a5f {
  strings:
    $key_2a5f = { 79 30 [2] 5d 3e [2] 76 12 [2] 58 30 [2] 4c 2b [2] 43 31 [2] 5d 2c [2] 5f 2d [2] 44 2b [2] 58 2c [2] 44 03 }

  condition:
    any of them
}