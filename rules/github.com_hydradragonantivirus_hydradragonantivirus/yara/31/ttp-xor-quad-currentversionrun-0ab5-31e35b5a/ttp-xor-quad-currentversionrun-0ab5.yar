rule TTP_XOR_QUAD_CurrentVersionRun_0ab5 {
  strings:
    $key_0ab5 = { 59 da [2] 7d d4 [2] 56 f8 [2] 78 da [2] 6c c1 [2] 63 db [2] 7d c6 [2] 7f c7 [2] 64 c1 [2] 78 c6 [2] 64 e9 }

  condition:
    any of them
}