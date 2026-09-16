rule TTP_XOR_QUAD_CurrentVersionRun_3fb6 {
  strings:
    $key_3fb6 = { 6c d9 [2] 48 d7 [2] 63 fb [2] 4d d9 [2] 59 c2 [2] 56 d8 [2] 48 c5 [2] 4a c4 [2] 51 c2 [2] 4d c5 [2] 51 ea }

  condition:
    any of them
}