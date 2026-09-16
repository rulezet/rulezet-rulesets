rule TTP_XOR_QUAD_CurrentVersionRun_2a4d {
  strings:
    $key_2a4d = { 79 22 [2] 5d 2c [2] 76 00 [2] 58 22 [2] 4c 39 [2] 43 23 [2] 5d 3e [2] 5f 3f [2] 44 39 [2] 58 3e [2] 44 11 }

  condition:
    any of them
}