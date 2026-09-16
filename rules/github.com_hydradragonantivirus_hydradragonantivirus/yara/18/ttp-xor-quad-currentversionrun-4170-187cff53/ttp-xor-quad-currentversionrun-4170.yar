rule TTP_XOR_QUAD_CurrentVersionRun_4170 {
  strings:
    $key_4170 = { 12 1f [2] 36 11 [2] 1d 3d [2] 33 1f [2] 27 04 [2] 28 1e [2] 36 03 [2] 34 02 [2] 2f 04 [2] 33 03 [2] 2f 2c }

  condition:
    any of them
}