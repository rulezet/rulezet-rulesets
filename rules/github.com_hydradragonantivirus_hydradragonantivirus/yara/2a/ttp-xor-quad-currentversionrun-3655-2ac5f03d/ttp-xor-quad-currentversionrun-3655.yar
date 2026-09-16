rule TTP_XOR_QUAD_CurrentVersionRun_3655 {
  strings:
    $key_3655 = { 65 3a [2] 41 34 [2] 6a 18 [2] 44 3a [2] 50 21 [2] 5f 3b [2] 41 26 [2] 43 27 [2] 58 21 [2] 44 26 [2] 58 09 }

  condition:
    any of them
}