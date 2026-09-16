rule TTP_XOR_QUAD_CurrentVersionRun_6f52 {
  strings:
    $key_6f52 = { 3c 3d [2] 18 33 [2] 33 1f [2] 1d 3d [2] 09 26 [2] 06 3c [2] 18 21 [2] 1a 20 [2] 01 26 [2] 1d 21 [2] 01 0e }

  condition:
    any of them
}