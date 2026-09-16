rule TTP_XOR_QUAD_CurrentVersionRun_89d1 {
  strings:
    $key_89d1 = { da be [2] fe b0 [2] d5 9c [2] fb be [2] ef a5 [2] e0 bf [2] fe a2 [2] fc a3 [2] e7 a5 [2] fb a2 [2] e7 8d }

  condition:
    any of them
}