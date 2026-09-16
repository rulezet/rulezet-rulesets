rule TTP_XOR_QUAD_CurrentVersionRun_5404 {
  strings:
    $key_5404 = { 07 6b [2] 23 65 [2] 08 49 [2] 26 6b [2] 32 70 [2] 3d 6a [2] 23 77 [2] 21 76 [2] 3a 70 [2] 26 77 [2] 3a 58 }

  condition:
    any of them
}