rule TTP_XOR_QUAD_CurrentVersionRun_2ab4 {
  strings:
    $key_2ab4 = { 79 db [2] 5d d5 [2] 76 f9 [2] 58 db [2] 4c c0 [2] 43 da [2] 5d c7 [2] 5f c6 [2] 44 c0 [2] 58 c7 [2] 44 e8 }

  condition:
    any of them
}