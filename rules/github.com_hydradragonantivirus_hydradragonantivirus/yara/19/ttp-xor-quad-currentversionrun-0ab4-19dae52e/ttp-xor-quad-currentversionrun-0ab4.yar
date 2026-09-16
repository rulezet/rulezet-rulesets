rule TTP_XOR_QUAD_CurrentVersionRun_0ab4 {
  strings:
    $key_0ab4 = { 59 db [2] 7d d5 [2] 56 f9 [2] 78 db [2] 6c c0 [2] 63 da [2] 7d c7 [2] 7f c6 [2] 64 c0 [2] 78 c7 [2] 64 e8 }

  condition:
    any of them
}