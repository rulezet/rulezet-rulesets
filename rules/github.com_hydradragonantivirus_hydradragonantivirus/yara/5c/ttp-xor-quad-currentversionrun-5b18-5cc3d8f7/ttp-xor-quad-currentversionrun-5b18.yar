rule TTP_XOR_QUAD_CurrentVersionRun_5b18 {
  strings:
    $key_5b18 = { 08 77 [2] 2c 79 [2] 07 55 [2] 29 77 [2] 3d 6c [2] 32 76 [2] 2c 6b [2] 2e 6a [2] 35 6c [2] 29 6b [2] 35 44 }

  condition:
    any of them
}