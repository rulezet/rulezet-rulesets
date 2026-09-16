rule TTP_XOR_QUAD_CurrentVersionRun_33b6 {
  strings:
    $key_33b6 = { 60 d9 [2] 44 d7 [2] 6f fb [2] 41 d9 [2] 55 c2 [2] 5a d8 [2] 44 c5 [2] 46 c4 [2] 5d c2 [2] 41 c5 [2] 5d ea }

  condition:
    any of them
}