rule TTP_XOR_QUAD_CurrentVersionRun_5446 {
  strings:
    $key_5446 = { 07 29 [2] 23 27 [2] 08 0b [2] 26 29 [2] 32 32 [2] 3d 28 [2] 23 35 [2] 21 34 [2] 3a 32 [2] 26 35 [2] 3a 1a }

  condition:
    any of them
}