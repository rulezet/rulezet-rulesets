rule TTP_XOR_QUAD_CurrentVersionRun_7452 {
  strings:
    $key_7452 = { 27 3d [2] 03 33 [2] 28 1f [2] 06 3d [2] 12 26 [2] 1d 3c [2] 03 21 [2] 01 20 [2] 1a 26 [2] 06 21 [2] 1a 0e }

  condition:
    any of them
}