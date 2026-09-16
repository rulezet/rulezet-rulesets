rule TTP_XOR_QUAD_CurrentVersionRun_662b {
  strings:
    $key_662b = { 35 44 [2] 11 4a [2] 3a 66 [2] 14 44 [2] 00 5f [2] 0f 45 [2] 11 58 [2] 13 59 [2] 08 5f [2] 14 58 [2] 08 77 }

  condition:
    any of them
}