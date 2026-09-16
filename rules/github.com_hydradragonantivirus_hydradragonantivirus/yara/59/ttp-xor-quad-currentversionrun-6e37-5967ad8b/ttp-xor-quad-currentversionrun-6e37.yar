rule TTP_XOR_QUAD_CurrentVersionRun_6e37 {
  strings:
    $key_6e37 = { 3d 58 [2] 19 56 [2] 32 7a [2] 1c 58 [2] 08 43 [2] 07 59 [2] 19 44 [2] 1b 45 [2] 00 43 [2] 1c 44 [2] 00 6b }

  condition:
    any of them
}