rule TTP_XOR_QUAD_CurrentVersionRun_5427 {
  strings:
    $key_5427 = { 07 48 [2] 23 46 [2] 08 6a [2] 26 48 [2] 32 53 [2] 3d 49 [2] 23 54 [2] 21 55 [2] 3a 53 [2] 26 54 [2] 3a 7b }

  condition:
    any of them
}