rule TTP_XOR_QUAD_CurrentVersionRun_7470 {
  strings:
    $key_7470 = { 27 1f [2] 03 11 [2] 28 3d [2] 06 1f [2] 12 04 [2] 1d 1e [2] 03 03 [2] 01 02 [2] 1a 04 [2] 06 03 [2] 1a 2c }

  condition:
    any of them
}