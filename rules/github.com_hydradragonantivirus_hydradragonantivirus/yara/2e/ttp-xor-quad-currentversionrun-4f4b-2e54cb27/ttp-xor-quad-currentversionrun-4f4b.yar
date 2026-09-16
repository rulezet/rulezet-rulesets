rule TTP_XOR_QUAD_CurrentVersionRun_4f4b {
  strings:
    $key_4f4b = { 1c 24 [2] 38 2a [2] 13 06 [2] 3d 24 [2] 29 3f [2] 26 25 [2] 38 38 [2] 3a 39 [2] 21 3f [2] 3d 38 [2] 21 17 }

  condition:
    any of them
}