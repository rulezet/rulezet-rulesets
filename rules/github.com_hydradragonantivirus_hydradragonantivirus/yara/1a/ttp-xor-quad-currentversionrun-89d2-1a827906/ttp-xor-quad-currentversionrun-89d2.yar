rule TTP_XOR_QUAD_CurrentVersionRun_89d2 {
  strings:
    $key_89d2 = { da bd [2] fe b3 [2] d5 9f [2] fb bd [2] ef a6 [2] e0 bc [2] fe a1 [2] fc a0 [2] e7 a6 [2] fb a1 [2] e7 8e }

  condition:
    any of them
}