rule TTP_XOR_QUAD_CurrentVersionRun_5b49 {
  strings:
    $key_5b49 = { 08 26 [2] 2c 28 [2] 07 04 [2] 29 26 [2] 3d 3d [2] 32 27 [2] 2c 3a [2] 2e 3b [2] 35 3d [2] 29 3a [2] 35 15 }

  condition:
    any of them
}