rule TTP_XOR_QUAD_CurrentVersionRun_7156 {
  strings:
    $key_7156 = { 22 39 [2] 06 37 [2] 2d 1b [2] 03 39 [2] 17 22 [2] 18 38 [2] 06 25 [2] 04 24 [2] 1f 22 [2] 03 25 [2] 1f 0a }

  condition:
    any of them
}