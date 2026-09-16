rule TTP_XOR_QUAD_CurrentVersionRun_715b {
  strings:
    $key_715b = { 22 34 [2] 06 3a [2] 2d 16 [2] 03 34 [2] 17 2f [2] 18 35 [2] 06 28 [2] 04 29 [2] 1f 2f [2] 03 28 [2] 1f 07 }

  condition:
    any of them
}