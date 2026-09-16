rule TTP_XOR_QUAD_CurrentVersionRun_5b25 {
  strings:
    $key_5b25 = { 08 4a [2] 2c 44 [2] 07 68 [2] 29 4a [2] 3d 51 [2] 32 4b [2] 2c 56 [2] 2e 57 [2] 35 51 [2] 29 56 [2] 35 79 }

  condition:
    any of them
}