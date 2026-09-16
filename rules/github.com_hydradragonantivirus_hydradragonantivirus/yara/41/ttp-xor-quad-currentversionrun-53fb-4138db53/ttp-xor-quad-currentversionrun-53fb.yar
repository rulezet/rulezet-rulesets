rule TTP_XOR_QUAD_CurrentVersionRun_53fb {
  strings:
    $key_53fb = { 00 94 [2] 24 9a [2] 0f b6 [2] 21 94 [2] 35 8f [2] 3a 95 [2] 24 88 [2] 26 89 [2] 3d 8f [2] 21 88 [2] 3d a7 }

  condition:
    any of them
}