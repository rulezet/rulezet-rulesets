rule TTP_XOR_QUAD_CurrentVersionRun_54fb {
  strings:
    $key_54fb = { 07 94 [2] 23 9a [2] 08 b6 [2] 26 94 [2] 32 8f [2] 3d 95 [2] 23 88 [2] 21 89 [2] 3a 8f [2] 26 88 [2] 3a a7 }

  condition:
    any of them
}