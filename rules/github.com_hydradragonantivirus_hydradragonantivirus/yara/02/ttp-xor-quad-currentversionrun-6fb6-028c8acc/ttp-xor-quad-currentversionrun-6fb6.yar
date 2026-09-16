rule TTP_XOR_QUAD_CurrentVersionRun_6fb6 {
  strings:
    $key_6fb6 = { 3c d9 [2] 18 d7 [2] 33 fb [2] 1d d9 [2] 09 c2 [2] 06 d8 [2] 18 c5 [2] 1a c4 [2] 01 c2 [2] 1d c5 [2] 01 ea }

  condition:
    any of them
}