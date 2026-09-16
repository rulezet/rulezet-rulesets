rule TTP_XOR_QUAD_CurrentVersionRun_4f42 {
  strings:
    $key_4f42 = { 1c 2d [2] 38 23 [2] 13 0f [2] 3d 2d [2] 29 36 [2] 26 2c [2] 38 31 [2] 3a 30 [2] 21 36 [2] 3d 31 [2] 21 1e }

  condition:
    any of them
}