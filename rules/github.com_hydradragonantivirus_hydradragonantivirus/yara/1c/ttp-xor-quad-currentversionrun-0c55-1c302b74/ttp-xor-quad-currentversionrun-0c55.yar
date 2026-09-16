rule TTP_XOR_QUAD_CurrentVersionRun_0c55 {
  strings:
    $key_0c55 = { 5f 3a [2] 7b 34 [2] 50 18 [2] 7e 3a [2] 6a 21 [2] 65 3b [2] 7b 26 [2] 79 27 [2] 62 21 [2] 7e 26 [2] 62 09 }

  condition:
    any of them
}