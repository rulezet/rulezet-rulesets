rule TTP_XOR_QUAD_CurrentVersionRun_6655 {
  strings:
    $key_6655 = { 35 3a [2] 11 34 [2] 3a 18 [2] 14 3a [2] 00 21 [2] 0f 3b [2] 11 26 [2] 13 27 [2] 08 21 [2] 14 26 [2] 08 09 }

  condition:
    any of them
}