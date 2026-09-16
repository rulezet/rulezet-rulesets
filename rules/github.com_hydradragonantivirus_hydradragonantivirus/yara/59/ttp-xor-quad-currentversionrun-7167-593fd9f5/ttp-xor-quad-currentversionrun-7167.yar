rule TTP_XOR_QUAD_CurrentVersionRun_7167 {
  strings:
    $key_7167 = { 22 08 [2] 06 06 [2] 2d 2a [2] 03 08 [2] 17 13 [2] 18 09 [2] 06 14 [2] 04 15 [2] 1f 13 [2] 03 14 [2] 1f 3b }

  condition:
    any of them
}