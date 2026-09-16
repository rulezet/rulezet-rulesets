rule TTP_XOR_QUAD_CurrentVersionRun_89a8 {
  strings:
    $key_89a8 = { da c7 [2] fe c9 [2] d5 e5 [2] fb c7 [2] ef dc [2] e0 c6 [2] fe db [2] fc da [2] e7 dc [2] fb db [2] e7 f4 }

  condition:
    any of them
}