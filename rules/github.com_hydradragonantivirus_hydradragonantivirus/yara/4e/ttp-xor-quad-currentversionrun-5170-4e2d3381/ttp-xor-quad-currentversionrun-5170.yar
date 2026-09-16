rule TTP_XOR_QUAD_CurrentVersionRun_5170 {
  strings:
    $key_5170 = { 02 1f [2] 26 11 [2] 0d 3d [2] 23 1f [2] 37 04 [2] 38 1e [2] 26 03 [2] 24 02 [2] 3f 04 [2] 23 03 [2] 3f 2c }

  condition:
    any of them
}