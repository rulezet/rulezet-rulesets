rule TTP_XOR_QUAD_CurrentVersionRun_89b5 {
  strings:
    $key_89b5 = { da da [2] fe d4 [2] d5 f8 [2] fb da [2] ef c1 [2] e0 db [2] fe c6 [2] fc c7 [2] e7 c1 [2] fb c6 [2] e7 e9 }

  condition:
    any of them
}