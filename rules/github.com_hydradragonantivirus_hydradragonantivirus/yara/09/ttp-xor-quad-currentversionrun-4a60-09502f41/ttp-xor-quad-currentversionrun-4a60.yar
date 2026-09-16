rule TTP_XOR_QUAD_CurrentVersionRun_4a60 {
  strings:
    $key_4a60 = { 19 0f [2] 3d 01 [2] 16 2d [2] 38 0f [2] 2c 14 [2] 23 0e [2] 3d 13 [2] 3f 12 [2] 24 14 [2] 38 13 [2] 24 3c }

  condition:
    any of them
}