rule TTP_XOR_QUAD_CurrentVersionRun_5464 {
  strings:
    $key_5464 = { 07 0b [2] 23 05 [2] 08 29 [2] 26 0b [2] 32 10 [2] 3d 0a [2] 23 17 [2] 21 16 [2] 3a 10 [2] 26 17 [2] 3a 38 }

  condition:
    any of them
}