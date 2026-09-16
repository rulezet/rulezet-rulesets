rule TTP_XOR_QUAD_CurrentVersionRun_7166 {
  strings:
    $key_7166 = { 22 09 [2] 06 07 [2] 2d 2b [2] 03 09 [2] 17 12 [2] 18 08 [2] 06 15 [2] 04 14 [2] 1f 12 [2] 03 15 [2] 1f 3a }

  condition:
    any of them
}