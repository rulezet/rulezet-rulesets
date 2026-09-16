rule TTP_XOR_QUAD_CurrentVersionRun_2a5c {
  strings:
    $key_2a5c = { 79 33 [2] 5d 3d [2] 76 11 [2] 58 33 [2] 4c 28 [2] 43 32 [2] 5d 2f [2] 5f 2e [2] 44 28 [2] 58 2f [2] 44 00 }

  condition:
    any of them
}