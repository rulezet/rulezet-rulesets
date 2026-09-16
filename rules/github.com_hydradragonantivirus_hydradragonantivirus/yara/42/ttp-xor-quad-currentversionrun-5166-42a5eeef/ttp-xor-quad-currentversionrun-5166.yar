rule TTP_XOR_QUAD_CurrentVersionRun_5166 {
  strings:
    $key_5166 = { 02 09 [2] 26 07 [2] 0d 2b [2] 23 09 [2] 37 12 [2] 38 08 [2] 26 15 [2] 24 14 [2] 3f 12 [2] 23 15 [2] 3f 3a }

  condition:
    any of them
}