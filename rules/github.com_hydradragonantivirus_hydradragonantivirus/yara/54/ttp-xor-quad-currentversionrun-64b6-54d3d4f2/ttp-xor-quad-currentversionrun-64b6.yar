rule TTP_XOR_QUAD_CurrentVersionRun_64b6 {
  strings:
    $key_64b6 = { 37 d9 [2] 13 d7 [2] 38 fb [2] 16 d9 [2] 02 c2 [2] 0d d8 [2] 13 c5 [2] 11 c4 [2] 0a c2 [2] 16 c5 [2] 0a ea }

  condition:
    any of them
}