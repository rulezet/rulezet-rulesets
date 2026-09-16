rule TTP_XOR_QUAD_CurrentVersionRun_5b60 {
  strings:
    $key_5b60 = { 08 0f [2] 2c 01 [2] 07 2d [2] 29 0f [2] 3d 14 [2] 32 0e [2] 2c 13 [2] 2e 12 [2] 35 14 [2] 29 13 [2] 35 3c }

  condition:
    any of them
}