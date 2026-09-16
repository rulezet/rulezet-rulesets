rule TTP_XOR_QUAD_CurrentVersionRun_4152 {
  strings:
    $key_4152 = { 12 3d [2] 36 33 [2] 1d 1f [2] 33 3d [2] 27 26 [2] 28 3c [2] 36 21 [2] 34 20 [2] 2f 26 [2] 33 21 [2] 2f 0e }

  condition:
    any of them
}