rule TTP_XOR_QUAD_CurrentVersionRun_7ab5 {
  strings:
    $key_7ab5 = { 29 da [2] 0d d4 [2] 26 f8 [2] 08 da [2] 1c c1 [2] 13 db [2] 0d c6 [2] 0f c7 [2] 14 c1 [2] 08 c6 [2] 14 e9 }

  condition:
    any of them
}