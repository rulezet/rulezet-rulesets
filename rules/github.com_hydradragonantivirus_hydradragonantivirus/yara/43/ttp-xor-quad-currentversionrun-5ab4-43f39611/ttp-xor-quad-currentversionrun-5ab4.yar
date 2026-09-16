rule TTP_XOR_QUAD_CurrentVersionRun_5ab4 {
  strings:
    $key_5ab4 = { 09 db [2] 2d d5 [2] 06 f9 [2] 28 db [2] 3c c0 [2] 33 da [2] 2d c7 [2] 2f c6 [2] 34 c0 [2] 28 c7 [2] 34 e8 }

  condition:
    any of them
}