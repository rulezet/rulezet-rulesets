rule TTP_XOR_QUAD_CurrentVersionRun_46b6 {
  strings:
    $key_46b6 = { 15 d9 [2] 31 d7 [2] 1a fb [2] 34 d9 [2] 20 c2 [2] 2f d8 [2] 31 c5 [2] 33 c4 [2] 28 c2 [2] 34 c5 [2] 28 ea }

  condition:
    any of them
}