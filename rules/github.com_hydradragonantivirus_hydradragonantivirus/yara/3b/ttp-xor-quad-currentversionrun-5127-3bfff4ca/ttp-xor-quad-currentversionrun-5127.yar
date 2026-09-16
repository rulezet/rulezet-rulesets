rule TTP_XOR_QUAD_CurrentVersionRun_5127 {
  strings:
    $key_5127 = { 02 48 [2] 26 46 [2] 0d 6a [2] 23 48 [2] 37 53 [2] 38 49 [2] 26 54 [2] 24 55 [2] 3f 53 [2] 23 54 [2] 3f 7b }

  condition:
    any of them
}