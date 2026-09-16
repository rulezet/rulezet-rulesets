rule TTP_XOR_QUAD_CurrentVersionRun_536b {
  strings:
    $key_536b = { 00 04 [2] 24 0a [2] 0f 26 [2] 21 04 [2] 35 1f [2] 3a 05 [2] 24 18 [2] 26 19 [2] 3d 1f [2] 21 18 [2] 3d 37 }

  condition:
    any of them
}