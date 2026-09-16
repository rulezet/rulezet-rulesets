rule TTP_XOR_QUAD_CurrentVersionRun_5479 {
  strings:
    $key_5479 = { 07 16 [2] 23 18 [2] 08 34 [2] 26 16 [2] 32 0d [2] 3d 17 [2] 23 0a [2] 21 0b [2] 3a 0d [2] 26 0a [2] 3a 25 }

  condition:
    any of them
}