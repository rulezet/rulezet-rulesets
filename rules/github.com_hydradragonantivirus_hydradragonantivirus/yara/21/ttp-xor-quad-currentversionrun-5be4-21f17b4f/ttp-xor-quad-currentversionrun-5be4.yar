rule TTP_XOR_QUAD_CurrentVersionRun_5be4 {
  strings:
    $key_5be4 = { 08 8b [2] 2c 85 [2] 07 a9 [2] 29 8b [2] 3d 90 [2] 32 8a [2] 2c 97 [2] 2e 96 [2] 35 90 [2] 29 97 [2] 35 b8 }

  condition:
    any of them
}