rule TTP_XOR_QUAD_CurrentVersionRun_7c55 {
  strings:
    $key_7c55 = { 2f 3a [2] 0b 34 [2] 20 18 [2] 0e 3a [2] 1a 21 [2] 15 3b [2] 0b 26 [2] 09 27 [2] 12 21 [2] 0e 26 [2] 12 09 }

  condition:
    any of them
}