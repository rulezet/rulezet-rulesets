rule TTP_XOR_QUAD_CurrentVersionRun_5646 {
  strings:
    $key_5646 = { 05 29 [2] 21 27 [2] 0a 0b [2] 24 29 [2] 30 32 [2] 3f 28 [2] 21 35 [2] 23 34 [2] 38 32 [2] 24 35 [2] 38 1a }

  condition:
    any of them
}