rule TTP_XOR_QUAD_CurrentVersionRun_56b6 {
  strings:
    $key_56b6 = { 05 d9 [2] 21 d7 [2] 0a fb [2] 24 d9 [2] 30 c2 [2] 3f d8 [2] 21 c5 [2] 23 c4 [2] 38 c2 [2] 24 c5 [2] 38 ea }

  condition:
    any of them
}