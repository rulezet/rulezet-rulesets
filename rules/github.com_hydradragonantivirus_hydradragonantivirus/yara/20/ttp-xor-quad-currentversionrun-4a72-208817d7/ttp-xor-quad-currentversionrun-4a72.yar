rule TTP_XOR_QUAD_CurrentVersionRun_4a72 {
  strings:
    $key_4a72 = { 19 1d [2] 3d 13 [2] 16 3f [2] 38 1d [2] 2c 06 [2] 23 1c [2] 3d 01 [2] 3f 00 [2] 24 06 [2] 38 01 [2] 24 2e }

  condition:
    any of them
}