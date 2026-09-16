rule TTP_XOR_QUAD_CurrentVersionRun_2a52 {
  strings:
    $key_2a52 = { 79 3d [2] 5d 33 [2] 76 1f [2] 58 3d [2] 4c 26 [2] 43 3c [2] 5d 21 [2] 5f 20 [2] 44 26 [2] 58 21 [2] 44 0e }

  condition:
    any of them
}