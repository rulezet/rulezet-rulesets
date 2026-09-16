rule TTP_XOR_QUAD_CurrentVersionRun_5457 {
  strings:
    $key_5457 = { 07 38 [2] 23 36 [2] 08 1a [2] 26 38 [2] 32 23 [2] 3d 39 [2] 23 24 [2] 21 25 [2] 3a 23 [2] 26 24 [2] 3a 0b }

  condition:
    any of them
}