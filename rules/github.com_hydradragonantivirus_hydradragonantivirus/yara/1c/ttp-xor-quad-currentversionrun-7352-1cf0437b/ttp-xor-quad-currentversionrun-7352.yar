rule TTP_XOR_QUAD_CurrentVersionRun_7352 {
  strings:
    $key_7352 = { 20 3d [2] 04 33 [2] 2f 1f [2] 01 3d [2] 15 26 [2] 1a 3c [2] 04 21 [2] 06 20 [2] 1d 26 [2] 01 21 [2] 1d 0e }

  condition:
    any of them
}