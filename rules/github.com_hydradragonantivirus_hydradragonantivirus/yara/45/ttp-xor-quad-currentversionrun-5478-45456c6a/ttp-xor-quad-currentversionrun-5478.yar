rule TTP_XOR_QUAD_CurrentVersionRun_5478 {
  strings:
    $key_5478 = { 07 17 [2] 23 19 [2] 08 35 [2] 26 17 [2] 32 0c [2] 3d 16 [2] 23 0b [2] 21 0a [2] 3a 0c [2] 26 0b [2] 3a 24 }

  condition:
    any of them
}