rule TTP_XOR_QUAD_CurrentVersionRun_2a70 {
  strings:
    $key_2a70 = { 79 1f [2] 5d 11 [2] 76 3d [2] 58 1f [2] 4c 04 [2] 43 1e [2] 5d 03 [2] 5f 02 [2] 44 04 [2] 58 03 [2] 44 2c }

  condition:
    any of them
}