rule TTP_XOR_QUAD_CurrentVersionRun_5154 {
  strings:
    $key_5154 = { 02 3b [2] 26 35 [2] 0d 19 [2] 23 3b [2] 37 20 [2] 38 3a [2] 26 27 [2] 24 26 [2] 3f 20 [2] 23 27 [2] 3f 08 }

  condition:
    any of them
}