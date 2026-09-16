rule TTP_XOR_QUAD_CurrentVersionRun_5b38 {
  strings:
    $key_5b38 = { 08 57 [2] 2c 59 [2] 07 75 [2] 29 57 [2] 3d 4c [2] 32 56 [2] 2c 4b [2] 2e 4a [2] 35 4c [2] 29 4b [2] 35 64 }

  condition:
    any of them
}