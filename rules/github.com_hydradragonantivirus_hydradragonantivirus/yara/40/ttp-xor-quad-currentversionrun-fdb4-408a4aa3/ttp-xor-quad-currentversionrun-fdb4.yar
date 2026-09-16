rule TTP_XOR_QUAD_CurrentVersionRun_fdb4 {
  strings:
    $key_fdb4 = { ae db [2] 8a d5 [2] a1 f9 [2] 8f db [2] 9b c0 [2] 94 da [2] 8a c7 [2] 88 c6 [2] 93 c0 [2] 8f c7 [2] 93 e8 }

  condition:
    any of them
}