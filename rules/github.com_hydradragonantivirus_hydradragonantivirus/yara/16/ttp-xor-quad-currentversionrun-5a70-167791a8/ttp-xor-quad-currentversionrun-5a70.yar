rule TTP_XOR_QUAD_CurrentVersionRun_5a70 {
  strings:
    $key_5a70 = { 09 1f [2] 2d 11 [2] 06 3d [2] 28 1f [2] 3c 04 [2] 33 1e [2] 2d 03 [2] 2f 02 [2] 34 04 [2] 28 03 [2] 34 2c }

  condition:
    any of them
}