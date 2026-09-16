rule TTP_XOR_QUAD_CurrentVersionRun_5455 {
  strings:
    $key_5455 = { 07 3a [2] 23 34 [2] 08 18 [2] 26 3a [2] 32 21 [2] 3d 3b [2] 23 26 [2] 21 27 [2] 3a 21 [2] 26 26 [2] 3a 09 }

  condition:
    any of them
}