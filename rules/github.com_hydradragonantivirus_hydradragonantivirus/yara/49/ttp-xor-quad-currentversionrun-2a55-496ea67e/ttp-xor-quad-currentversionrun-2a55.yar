rule TTP_XOR_QUAD_CurrentVersionRun_2a55 {
  strings:
    $key_2a55 = { 79 3a [2] 5d 34 [2] 76 18 [2] 58 3a [2] 4c 21 [2] 43 3b [2] 5d 26 [2] 5f 27 [2] 44 21 [2] 58 26 [2] 44 09 }

  condition:
    any of them
}