rule TTP_XOR_QUAD_CurrentVersionRun_7a55 {
  strings:
    $key_7a55 = { 29 3a [2] 0d 34 [2] 26 18 [2] 08 3a [2] 1c 21 [2] 13 3b [2] 0d 26 [2] 0f 27 [2] 14 21 [2] 08 26 [2] 14 09 }

  condition:
    any of them
}