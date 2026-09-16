rule TTP_XOR_QUAD_CurrentVersionRun_6e67 {
  strings:
    $key_6e67 = { 3d 08 [2] 19 06 [2] 32 2a [2] 1c 08 [2] 08 13 [2] 07 09 [2] 19 14 [2] 1b 15 [2] 00 13 [2] 1c 14 [2] 00 3b }

  condition:
    any of them
}