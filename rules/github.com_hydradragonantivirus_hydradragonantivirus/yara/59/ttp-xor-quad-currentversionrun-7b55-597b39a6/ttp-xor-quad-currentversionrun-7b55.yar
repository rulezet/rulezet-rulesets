rule TTP_XOR_QUAD_CurrentVersionRun_7b55 {
  strings:
    $key_7b55 = { 28 3a [2] 0c 34 [2] 27 18 [2] 09 3a [2] 1d 21 [2] 12 3b [2] 0c 26 [2] 0e 27 [2] 15 21 [2] 09 26 [2] 15 09 }

  condition:
    any of them
}