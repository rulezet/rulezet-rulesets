rule TTP_XOR_QUAD_CurrentVersionRun_4fb6 {
  strings:
    $key_4fb6 = { 1c d9 [2] 38 d7 [2] 13 fb [2] 3d d9 [2] 29 c2 [2] 26 d8 [2] 38 c5 [2] 3a c4 [2] 21 c2 [2] 3d c5 [2] 21 ea }

  condition:
    any of them
}