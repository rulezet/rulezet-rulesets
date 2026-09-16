rule TTP_XOR_QUAD_CurrentVersionRun_5b05 {
  strings:
    $key_5b05 = { 08 6a [2] 2c 64 [2] 07 48 [2] 29 6a [2] 3d 71 [2] 32 6b [2] 2c 76 [2] 2e 77 [2] 35 71 [2] 29 76 [2] 35 59 }

  condition:
    any of them
}