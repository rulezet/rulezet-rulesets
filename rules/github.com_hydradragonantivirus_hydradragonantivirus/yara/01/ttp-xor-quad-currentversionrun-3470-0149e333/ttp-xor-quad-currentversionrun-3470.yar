rule TTP_XOR_QUAD_CurrentVersionRun_3470 {
  strings:
    $key_3470 = { 67 1f [2] 43 11 [2] 68 3d [2] 46 1f [2] 52 04 [2] 5d 1e [2] 43 03 [2] 41 02 [2] 5a 04 [2] 46 03 [2] 5a 2c }

  condition:
    any of them
}