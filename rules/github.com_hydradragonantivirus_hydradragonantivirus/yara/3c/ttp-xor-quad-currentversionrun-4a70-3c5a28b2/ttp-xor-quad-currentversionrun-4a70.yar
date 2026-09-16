rule TTP_XOR_QUAD_CurrentVersionRun_4a70 {
  strings:
    $key_4a70 = { 19 1f [2] 3d 11 [2] 16 3d [2] 38 1f [2] 2c 04 [2] 23 1e [2] 3d 03 [2] 3f 02 [2] 24 04 [2] 38 03 [2] 24 2c }

  condition:
    any of them
}