rule TTP_XOR_QUAD_CurrentVersionRun_5639 {
  strings:
    $key_5639 = { 05 56 [2] 21 58 [2] 0a 74 [2] 24 56 [2] 30 4d [2] 3f 57 [2] 21 4a [2] 23 4b [2] 38 4d [2] 24 4a [2] 38 65 }

  condition:
    any of them
}