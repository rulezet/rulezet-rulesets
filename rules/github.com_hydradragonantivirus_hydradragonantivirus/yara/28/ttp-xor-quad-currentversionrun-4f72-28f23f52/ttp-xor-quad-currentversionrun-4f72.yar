rule TTP_XOR_QUAD_CurrentVersionRun_4f72 {
  strings:
    $key_4f72 = { 1c 1d [2] 38 13 [2] 13 3f [2] 3d 1d [2] 29 06 [2] 26 1c [2] 38 01 [2] 3a 00 [2] 21 06 [2] 3d 01 [2] 21 2e }

  condition:
    any of them
}