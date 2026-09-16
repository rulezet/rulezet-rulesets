rule TTP_XOR_QUAD_CurrentVersionRun_5224 {
  strings:
    $key_5224 = { 01 4b [2] 25 45 [2] 0e 69 [2] 20 4b [2] 34 50 [2] 3b 4a [2] 25 57 [2] 27 56 [2] 3c 50 [2] 20 57 [2] 3c 78 }

  condition:
    any of them
}