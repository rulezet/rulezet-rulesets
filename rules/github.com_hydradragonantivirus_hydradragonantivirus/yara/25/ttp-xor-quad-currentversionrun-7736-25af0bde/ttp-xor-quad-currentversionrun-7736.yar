rule TTP_XOR_QUAD_CurrentVersionRun_7736 {
  strings:
    $key_7736 = { 24 59 [2] 00 57 [2] 2b 7b [2] 05 59 [2] 11 42 [2] 1e 58 [2] 00 45 [2] 02 44 [2] 19 42 [2] 05 45 [2] 19 6a }

  condition:
    any of them
}