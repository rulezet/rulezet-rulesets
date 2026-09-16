rule TTP_XOR_QUAD_CurrentVersionRun_544b {
  strings:
    $key_544b = { 07 24 [2] 23 2a [2] 08 06 [2] 26 24 [2] 32 3f [2] 3d 25 [2] 23 38 [2] 21 39 [2] 3a 3f [2] 26 38 [2] 3a 17 }

  condition:
    any of them
}