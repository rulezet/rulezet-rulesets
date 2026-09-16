rule TTP_XOR_QUAD_CurrentVersionRun_8ca8 {
  strings:
    $key_8ca8 = { df c7 [2] fb c9 [2] d0 e5 [2] fe c7 [2] ea dc [2] e5 c6 [2] fb db [2] f9 da [2] e2 dc [2] fe db [2] e2 f4 }

  condition:
    any of them
}