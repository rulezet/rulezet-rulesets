rule TTP_XOR_QUAD_CurrentVersionRun_5624 {
  strings:
    $key_5624 = { 05 4b [2] 21 45 [2] 0a 69 [2] 24 4b [2] 30 50 [2] 3f 4a [2] 21 57 [2] 23 56 [2] 38 50 [2] 24 57 [2] 38 78 }

  condition:
    any of them
}