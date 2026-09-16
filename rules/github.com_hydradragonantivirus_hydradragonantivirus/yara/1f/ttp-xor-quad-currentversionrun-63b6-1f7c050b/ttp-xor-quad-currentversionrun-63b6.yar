rule TTP_XOR_QUAD_CurrentVersionRun_63b6 {
  strings:
    $key_63b6 = { 30 d9 [2] 14 d7 [2] 3f fb [2] 11 d9 [2] 05 c2 [2] 0a d8 [2] 14 c5 [2] 16 c4 [2] 0d c2 [2] 11 c5 [2] 0d ea }

  condition:
    any of them
}