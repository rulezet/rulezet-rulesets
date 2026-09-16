rule TTP_XOR_QUAD_CurrentVersionRun_5454 {
  strings:
    $key_5454 = { 07 3b [2] 23 35 [2] 08 19 [2] 26 3b [2] 32 20 [2] 3d 3a [2] 23 27 [2] 21 26 [2] 3a 20 [2] 26 27 [2] 3a 08 }

  condition:
    any of them
}