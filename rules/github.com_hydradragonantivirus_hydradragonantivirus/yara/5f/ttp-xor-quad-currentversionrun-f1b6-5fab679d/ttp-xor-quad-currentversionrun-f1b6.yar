rule TTP_XOR_QUAD_CurrentVersionRun_f1b6 {
  strings:
    $key_f1b6 = { a2 d9 [2] 86 d7 [2] ad fb [2] 83 d9 [2] 97 c2 [2] 98 d8 [2] 86 c5 [2] 84 c4 [2] 9f c2 [2] 83 c5 [2] 9f ea }

  condition:
    any of them
}