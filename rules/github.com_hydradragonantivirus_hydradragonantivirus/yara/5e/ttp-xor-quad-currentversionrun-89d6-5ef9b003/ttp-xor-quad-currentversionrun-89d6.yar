rule TTP_XOR_QUAD_CurrentVersionRun_89d6 {
  strings:
    $key_89d6 = { da b9 [2] fe b7 [2] d5 9b [2] fb b9 [2] ef a2 [2] e0 b8 [2] fe a5 [2] fc a4 [2] e7 a2 [2] fb a5 [2] e7 8a }

  condition:
    any of them
}