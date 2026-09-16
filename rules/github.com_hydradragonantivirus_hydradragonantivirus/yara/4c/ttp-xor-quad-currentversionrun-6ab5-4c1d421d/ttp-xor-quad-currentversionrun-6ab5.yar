rule TTP_XOR_QUAD_CurrentVersionRun_6ab5 {
  strings:
    $key_6ab5 = { 39 da [2] 1d d4 [2] 36 f8 [2] 18 da [2] 0c c1 [2] 03 db [2] 1d c6 [2] 1f c7 [2] 04 c1 [2] 18 c6 [2] 04 e9 }

  condition:
    any of them
}