rule TTP_XOR_QUAD_CurrentVersionRun_5442 {
  strings:
    $key_5442 = { 07 2d [2] 23 23 [2] 08 0f [2] 26 2d [2] 32 36 [2] 3d 2c [2] 23 31 [2] 21 30 [2] 3a 36 [2] 26 31 [2] 3a 1e }

  condition:
    any of them
}