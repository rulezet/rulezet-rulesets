rule TTP_XOR_QUAD_CurrentVersionRun_23b6 {
  strings:
    $key_23b6 = { 70 d9 [2] 54 d7 [2] 7f fb [2] 51 d9 [2] 45 c2 [2] 4a d8 [2] 54 c5 [2] 56 c4 [2] 4d c2 [2] 51 c5 [2] 4d ea }

  condition:
    any of them
}