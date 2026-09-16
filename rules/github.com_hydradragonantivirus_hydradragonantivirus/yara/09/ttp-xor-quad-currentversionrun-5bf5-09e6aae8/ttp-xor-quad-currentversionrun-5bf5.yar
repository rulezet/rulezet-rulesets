rule TTP_XOR_QUAD_CurrentVersionRun_5bf5 {
  strings:
    $key_5bf5 = { 08 9a [2] 2c 94 [2] 07 b8 [2] 29 9a [2] 3d 81 [2] 32 9b [2] 2c 86 [2] 2e 87 [2] 35 81 [2] 29 86 [2] 35 a9 }

  condition:
    any of them
}