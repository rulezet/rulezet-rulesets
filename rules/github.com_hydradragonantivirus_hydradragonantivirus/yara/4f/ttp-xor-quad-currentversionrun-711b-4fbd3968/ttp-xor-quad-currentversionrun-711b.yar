rule TTP_XOR_QUAD_CurrentVersionRun_711b {
  strings:
    $key_711b = { 22 74 [2] 06 7a [2] 2d 56 [2] 03 74 [2] 17 6f [2] 18 75 [2] 06 68 [2] 04 69 [2] 1f 6f [2] 03 68 [2] 1f 47 }

  condition:
    any of them
}