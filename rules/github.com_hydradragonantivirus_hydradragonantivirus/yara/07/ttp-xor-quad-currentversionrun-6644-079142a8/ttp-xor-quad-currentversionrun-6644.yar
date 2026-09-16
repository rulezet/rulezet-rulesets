rule TTP_XOR_QUAD_CurrentVersionRun_6644 {
  strings:
    $key_6644 = { 35 2b [2] 11 25 [2] 3a 09 [2] 14 2b [2] 00 30 [2] 0f 2a [2] 11 37 [2] 13 36 [2] 08 30 [2] 14 37 [2] 08 18 }

  condition:
    any of them
}