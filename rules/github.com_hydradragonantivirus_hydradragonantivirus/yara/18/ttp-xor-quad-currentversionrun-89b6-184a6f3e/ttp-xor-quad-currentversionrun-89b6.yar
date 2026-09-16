rule TTP_XOR_QUAD_CurrentVersionRun_89b6 {
  strings:
    $key_89b6 = { da d9 [2] fe d7 [2] d5 fb [2] fb d9 [2] ef c2 [2] e0 d8 [2] fe c5 [2] fc c4 [2] e7 c2 [2] fb c5 [2] e7 ea }

  condition:
    any of them
}