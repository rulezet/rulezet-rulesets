rule TTP_XOR_QUAD_CurrentVersionRun_7ab4 {
  strings:
    $key_7ab4 = { 29 db [2] 0d d5 [2] 26 f9 [2] 08 db [2] 1c c0 [2] 13 da [2] 0d c7 [2] 0f c6 [2] 14 c0 [2] 08 c7 [2] 14 e8 }

  condition:
    any of them
}