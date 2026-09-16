rule TTP_XOR_QUAD_CurrentVersionRun_5b15 {
  strings:
    $key_5b15 = { 08 7a [2] 2c 74 [2] 07 58 [2] 29 7a [2] 3d 61 [2] 32 7b [2] 2c 66 [2] 2e 67 [2] 35 61 [2] 29 66 [2] 35 49 }

  condition:
    any of them
}