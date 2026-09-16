rule TTP_XOR_QUAD_CurrentVersionRun_5155 {
  strings:
    $key_5155 = { 02 3a [2] 26 34 [2] 0d 18 [2] 23 3a [2] 37 21 [2] 38 3b [2] 26 26 [2] 24 27 [2] 3f 21 [2] 23 26 [2] 3f 09 }

  condition:
    any of them
}