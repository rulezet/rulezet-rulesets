rule TTP_XOR_QUAD_CurrentVersionRun_5f52 {
  strings:
    $key_5f52 = { 0c 3d [2] 28 33 [2] 03 1f [2] 2d 3d [2] 39 26 [2] 36 3c [2] 28 21 [2] 2a 20 [2] 31 26 [2] 2d 21 [2] 31 0e }

  condition:
    any of them
}