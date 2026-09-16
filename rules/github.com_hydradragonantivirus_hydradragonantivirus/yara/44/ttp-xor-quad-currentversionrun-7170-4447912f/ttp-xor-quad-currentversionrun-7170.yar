rule TTP_XOR_QUAD_CurrentVersionRun_7170 {
  strings:
    $key_7170 = { 22 1f [2] 06 11 [2] 2d 3d [2] 03 1f [2] 17 04 [2] 18 1e [2] 06 03 [2] 04 02 [2] 1f 04 [2] 03 03 [2] 1f 2c }

  condition:
    any of them
}