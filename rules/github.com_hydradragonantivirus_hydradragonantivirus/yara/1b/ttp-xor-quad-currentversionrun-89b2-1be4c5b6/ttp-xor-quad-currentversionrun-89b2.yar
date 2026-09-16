rule TTP_XOR_QUAD_CurrentVersionRun_89b2 {
  strings:
    $key_89b2 = { da dd [2] fe d3 [2] d5 ff [2] fb dd [2] ef c6 [2] e0 dc [2] fe c1 [2] fc c0 [2] e7 c6 [2] fb c1 [2] e7 ee }

  condition:
    any of them
}