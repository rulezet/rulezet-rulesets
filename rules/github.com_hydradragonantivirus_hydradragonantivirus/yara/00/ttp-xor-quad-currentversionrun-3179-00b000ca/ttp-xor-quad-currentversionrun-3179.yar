rule TTP_XOR_QUAD_CurrentVersionRun_3179 {
  strings:
    $key_3179 = { 62 16 [2] 46 18 [2] 6d 34 [2] 43 16 [2] 57 0d [2] 58 17 [2] 46 0a [2] 44 0b [2] 5f 0d [2] 43 0a [2] 5f 25 }

  condition:
    any of them
}