rule TTP_XOR_QUAD_CurrentVersionRun_4875 {
  strings:
    $key_4875 = { 1b 1a [2] 3f 14 [2] 14 38 [2] 3a 1a [2] 2e 01 [2] 21 1b [2] 3f 06 [2] 3d 07 [2] 26 01 [2] 3a 06 [2] 26 29 }

  condition:
    any of them
}