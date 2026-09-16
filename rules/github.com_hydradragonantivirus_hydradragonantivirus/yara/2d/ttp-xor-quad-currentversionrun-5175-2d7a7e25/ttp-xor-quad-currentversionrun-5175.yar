rule TTP_XOR_QUAD_CurrentVersionRun_5175 {
  strings:
    $key_5175 = { 02 1a [2] 26 14 [2] 0d 38 [2] 23 1a [2] 37 01 [2] 38 1b [2] 26 06 [2] 24 07 [2] 3f 01 [2] 23 06 [2] 3f 29 }

  condition:
    any of them
}