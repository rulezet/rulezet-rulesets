rule TTP_XOR_QUAD_CurrentVersionRun_89a9 {
  strings:
    $key_89a9 = { da c6 [2] fe c8 [2] d5 e4 [2] fb c6 [2] ef dd [2] e0 c7 [2] fe da [2] fc db [2] e7 dd [2] fb da [2] e7 f5 }

  condition:
    any of them
}