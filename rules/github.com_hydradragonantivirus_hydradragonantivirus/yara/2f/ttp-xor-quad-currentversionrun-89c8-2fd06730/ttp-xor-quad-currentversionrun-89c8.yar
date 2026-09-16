rule TTP_XOR_QUAD_CurrentVersionRun_89c8 {
  strings:
    $key_89c8 = { da a7 [2] fe a9 [2] d5 85 [2] fb a7 [2] ef bc [2] e0 a6 [2] fe bb [2] fc ba [2] e7 bc [2] fb bb [2] e7 94 }

  condition:
    any of them
}