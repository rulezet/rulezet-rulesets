rule TTP_XOR_QUAD_CurrentVersionRun_4470 {
  strings:
    $key_4470 = { 17 1f [2] 33 11 [2] 18 3d [2] 36 1f [2] 22 04 [2] 2d 1e [2] 33 03 [2] 31 02 [2] 2a 04 [2] 36 03 [2] 2a 2c }

  condition:
    any of them
}