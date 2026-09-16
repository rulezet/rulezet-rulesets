rule TTP_XOR_QUAD_CurrentVersionRun_6142 {
  strings:
    $key_6142 = { 32 2d [2] 16 23 [2] 3d 0f [2] 13 2d [2] 07 36 [2] 08 2c [2] 16 31 [2] 14 30 [2] 0f 36 [2] 13 31 [2] 0f 1e }

  condition:
    any of them
}