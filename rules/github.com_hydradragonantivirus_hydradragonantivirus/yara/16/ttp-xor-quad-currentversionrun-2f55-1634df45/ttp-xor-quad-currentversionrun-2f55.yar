rule TTP_XOR_QUAD_CurrentVersionRun_2f55 {
  strings:
    $key_2f55 = { 7c 3a [2] 58 34 [2] 73 18 [2] 5d 3a [2] 49 21 [2] 46 3b [2] 58 26 [2] 5a 27 [2] 41 21 [2] 5d 26 [2] 41 09 }

  condition:
    any of them
}