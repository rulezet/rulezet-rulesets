rule TTP_XOR_QUAD_CurrentVersionRun_5b42 {
  strings:
    $key_5b42 = { 08 2d [2] 2c 23 [2] 07 0f [2] 29 2d [2] 3d 36 [2] 32 2c [2] 2c 31 [2] 2e 30 [2] 35 36 [2] 29 31 [2] 35 1e }

  condition:
    any of them
}