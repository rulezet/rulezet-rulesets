rule TTP_XOR_QUAD_CurrentVersionRun_6e07 {
  strings:
    $key_6e07 = { 3d 68 [2] 19 66 [2] 32 4a [2] 1c 68 [2] 08 73 [2] 07 69 [2] 19 74 [2] 1b 75 [2] 00 73 [2] 1c 74 [2] 00 5b }

  condition:
    any of them
}