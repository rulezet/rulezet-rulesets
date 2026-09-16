rule TTP_XOR_QUAD_CurrentVersionRun_6e75 {
  strings:
    $key_6e75 = { 3d 1a [2] 19 14 [2] 32 38 [2] 1c 1a [2] 08 01 [2] 07 1b [2] 19 06 [2] 1b 07 [2] 00 01 [2] 1c 06 [2] 00 29 }

  condition:
    any of them
}