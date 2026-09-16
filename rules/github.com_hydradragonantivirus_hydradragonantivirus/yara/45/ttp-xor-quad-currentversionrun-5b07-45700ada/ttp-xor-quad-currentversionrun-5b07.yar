rule TTP_XOR_QUAD_CurrentVersionRun_5b07 {
  strings:
    $key_5b07 = { 08 68 [2] 2c 66 [2] 07 4a [2] 29 68 [2] 3d 73 [2] 32 69 [2] 2c 74 [2] 2e 75 [2] 35 73 [2] 29 74 [2] 35 5b }

  condition:
    any of them
}