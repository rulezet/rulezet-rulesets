rule TTP_XOR_QUAD_CurrentVersionRun_f4b6 {
  strings:
    $key_f4b6 = { a7 d9 [2] 83 d7 [2] a8 fb [2] 86 d9 [2] 92 c2 [2] 9d d8 [2] 83 c5 [2] 81 c4 [2] 9a c2 [2] 86 c5 [2] 9a ea }

  condition:
    any of them
}