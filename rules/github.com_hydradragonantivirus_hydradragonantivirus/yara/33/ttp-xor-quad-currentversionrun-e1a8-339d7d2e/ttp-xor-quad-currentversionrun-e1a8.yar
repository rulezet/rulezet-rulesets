rule TTP_XOR_QUAD_CurrentVersionRun_e1a8 {
  strings:
    $key_e1a8 = { b2 c7 [2] 96 c9 [2] bd e5 [2] 93 c7 [2] 87 dc [2] 88 c6 [2] 96 db [2] 94 da [2] 8f dc [2] 93 db [2] 8f f4 }

  condition:
    any of them
}