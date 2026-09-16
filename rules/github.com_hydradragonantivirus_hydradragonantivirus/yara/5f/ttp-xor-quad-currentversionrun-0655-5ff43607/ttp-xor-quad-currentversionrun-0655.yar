rule TTP_XOR_QUAD_CurrentVersionRun_0655 {
  strings:
    $key_0655 = { 55 3a [2] 71 34 [2] 5a 18 [2] 74 3a [2] 60 21 [2] 6f 3b [2] 71 26 [2] 73 27 [2] 68 21 [2] 74 26 [2] 68 09 }

  condition:
    any of them
}