rule TTP_XOR_QUAD_CurrentVersionRun_2155 {
  strings:
    $key_2155 = { 72 3a [2] 56 34 [2] 7d 18 [2] 53 3a [2] 47 21 [2] 48 3b [2] 56 26 [2] 54 27 [2] 4f 21 [2] 53 26 [2] 4f 09 }

  condition:
    any of them
}