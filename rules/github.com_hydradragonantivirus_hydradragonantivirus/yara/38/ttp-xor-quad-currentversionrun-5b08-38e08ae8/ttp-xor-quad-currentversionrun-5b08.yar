rule TTP_XOR_QUAD_CurrentVersionRun_5b08 {
  strings:
    $key_5b08 = { 08 67 [2] 2c 69 [2] 07 45 [2] 29 67 [2] 3d 7c [2] 32 66 [2] 2c 7b [2] 2e 7a [2] 35 7c [2] 29 7b [2] 35 54 }

  condition:
    any of them
}