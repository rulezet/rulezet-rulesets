rule TTP_XOR_QUAD_CurrentVersionRun_0355 {
  strings:
    $key_0355 = { 50 3a [2] 74 34 [2] 5f 18 [2] 71 3a [2] 65 21 [2] 6a 3b [2] 74 26 [2] 76 27 [2] 6d 21 [2] 71 26 [2] 6d 09 }

  condition:
    any of them
}