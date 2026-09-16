rule TTP_XOR_QUAD_CurrentVersionRun_89c3 {
  strings:
    $key_89c3 = { da ac [2] fe a2 [2] d5 8e [2] fb ac [2] ef b7 [2] e0 ad [2] fe b0 [2] fc b1 [2] e7 b7 [2] fb b0 [2] e7 9f }

  condition:
    any of them
}