rule TTP_XOR_QUAD_CurrentVersionRun_89b4 {
  strings:
    $key_89b4 = { da db [2] fe d5 [2] d5 f9 [2] fb db [2] ef c0 [2] e0 da [2] fe c7 [2] fc c6 [2] e7 c0 [2] fb c7 [2] e7 e8 }

  condition:
    any of them
}