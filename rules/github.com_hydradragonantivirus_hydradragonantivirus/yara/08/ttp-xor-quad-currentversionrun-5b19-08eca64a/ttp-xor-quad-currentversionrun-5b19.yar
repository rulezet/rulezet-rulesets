rule TTP_XOR_QUAD_CurrentVersionRun_5b19 {
  strings:
    $key_5b19 = { 08 76 [2] 2c 78 [2] 07 54 [2] 29 76 [2] 3d 6d [2] 32 77 [2] 2c 6a [2] 2e 6b [2] 35 6d [2] 29 6a [2] 35 45 }

  condition:
    any of them
}