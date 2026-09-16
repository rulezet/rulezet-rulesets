rule TTP_XOR_QUAD_CurrentVersionRun_7fb6 {
  strings:
    $key_7fb6 = { 2c d9 [2] 08 d7 [2] 23 fb [2] 0d d9 [2] 19 c2 [2] 16 d8 [2] 08 c5 [2] 0a c4 [2] 11 c2 [2] 0d c5 [2] 11 ea }

  condition:
    any of them
}