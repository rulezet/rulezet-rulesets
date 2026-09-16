rule TTP_XOR_QUAD_CurrentVersionRun_6364 {
  strings:
    $key_6364 = { 30 0b [2] 14 05 [2] 3f 29 [2] 11 0b [2] 05 10 [2] 0a 0a [2] 14 17 [2] 16 16 [2] 0d 10 [2] 11 17 [2] 0d 38 }

  condition:
    any of them
}