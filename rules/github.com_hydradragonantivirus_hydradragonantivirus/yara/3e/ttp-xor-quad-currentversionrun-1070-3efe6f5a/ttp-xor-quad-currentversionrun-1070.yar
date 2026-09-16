rule TTP_XOR_QUAD_CurrentVersionRun_1070 {
  strings:
    $key_1070 = { 43 1f [2] 67 11 [2] 4c 3d [2] 62 1f [2] 76 04 [2] 79 1e [2] 67 03 [2] 65 02 [2] 7e 04 [2] 62 03 [2] 7e 2c }

  condition:
    any of them
}