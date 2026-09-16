rule TTP_XOR_QUAD_CurrentVersionRun_5636 {
  strings:
    $key_5636 = { 05 59 [2] 21 57 [2] 0a 7b [2] 24 59 [2] 30 42 [2] 3f 58 [2] 21 45 [2] 23 44 [2] 38 42 [2] 24 45 [2] 38 6a }

  condition:
    any of them
}