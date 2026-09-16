rule TTP_XOR_QUAD_CurrentVersionRun_89ae {
  strings:
    $key_89ae = { da c1 [2] fe cf [2] d5 e3 [2] fb c1 [2] ef da [2] e0 c0 [2] fe dd [2] fc dc [2] e7 da [2] fb dd [2] e7 f2 }

  condition:
    any of them
}