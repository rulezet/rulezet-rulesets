rule TTP_XOR_QUAD_CurrentVersionRun_54e4 {
  strings:
    $key_54e4 = { 07 8b [2] 23 85 [2] 08 a9 [2] 26 8b [2] 32 90 [2] 3d 8a [2] 23 97 [2] 21 96 [2] 3a 90 [2] 26 97 [2] 3a b8 }

  condition:
    any of them
}