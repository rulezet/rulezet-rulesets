rule TTP_XOR_QUAD_CurrentVersionRun_4f6b {
  strings:
    $key_4f6b = { 1c 04 [2] 38 0a [2] 13 26 [2] 3d 04 [2] 29 1f [2] 26 05 [2] 38 18 [2] 3a 19 [2] 21 1f [2] 3d 18 [2] 21 37 }

  condition:
    any of them
}