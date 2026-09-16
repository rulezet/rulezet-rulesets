rule TTP_XOR_QUAD_CurrentVersionRun_4d55 {
  strings:
    $key_4d55 = { 1e 3a [2] 3a 34 [2] 11 18 [2] 3f 3a [2] 2b 21 [2] 24 3b [2] 3a 26 [2] 38 27 [2] 23 21 [2] 3f 26 [2] 23 09 }

  condition:
    any of them
}