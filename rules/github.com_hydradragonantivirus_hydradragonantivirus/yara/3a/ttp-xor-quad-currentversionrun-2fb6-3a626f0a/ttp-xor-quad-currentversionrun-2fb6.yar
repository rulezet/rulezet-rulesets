rule TTP_XOR_QUAD_CurrentVersionRun_2fb6 {
  strings:
    $key_2fb6 = { 7c d9 [2] 58 d7 [2] 73 fb [2] 5d d9 [2] 49 c2 [2] 46 d8 [2] 58 c5 [2] 5a c4 [2] 41 c2 [2] 5d c5 [2] 41 ea }

  condition:
    any of them
}