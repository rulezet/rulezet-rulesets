rule TTP_XOR_QUAD_CurrentVersionRun_89c6 {
  strings:
    $key_89c6 = { da a9 [2] fe a7 [2] d5 8b [2] fb a9 [2] ef b2 [2] e0 a8 [2] fe b5 [2] fc b4 [2] e7 b2 [2] fb b5 [2] e7 9a }

  condition:
    any of them
}