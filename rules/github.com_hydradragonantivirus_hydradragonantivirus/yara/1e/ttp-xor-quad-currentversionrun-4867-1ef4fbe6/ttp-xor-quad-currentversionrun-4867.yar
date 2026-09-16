rule TTP_XOR_QUAD_CurrentVersionRun_4867 {
  strings:
    $key_4867 = { 1b 08 [2] 3f 06 [2] 14 2a [2] 3a 08 [2] 2e 13 [2] 21 09 [2] 3f 14 [2] 3d 15 [2] 26 13 [2] 3a 14 [2] 26 3b }

  condition:
    any of them
}