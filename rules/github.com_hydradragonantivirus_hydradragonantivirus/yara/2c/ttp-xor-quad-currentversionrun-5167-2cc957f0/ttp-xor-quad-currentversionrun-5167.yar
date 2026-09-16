rule TTP_XOR_QUAD_CurrentVersionRun_5167 {
  strings:
    $key_5167 = { 02 08 [2] 26 06 [2] 0d 2a [2] 23 08 [2] 37 13 [2] 38 09 [2] 26 14 [2] 24 15 [2] 3f 13 [2] 23 14 [2] 3f 3b }

  condition:
    any of them
}