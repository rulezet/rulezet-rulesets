rule TTP_XOR_QUAD_CurrentVersionRun_530b {
  strings:
    $key_530b = { 00 64 [2] 24 6a [2] 0f 46 [2] 21 64 [2] 35 7f [2] 3a 65 [2] 24 78 [2] 26 79 [2] 3d 7f [2] 21 78 [2] 3d 57 }

  condition:
    any of them
}