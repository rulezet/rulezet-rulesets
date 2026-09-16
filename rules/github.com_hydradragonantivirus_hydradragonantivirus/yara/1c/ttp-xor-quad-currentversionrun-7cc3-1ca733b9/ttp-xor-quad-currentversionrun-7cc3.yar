rule TTP_XOR_QUAD_CurrentVersionRun_7cc3 {
  strings:
    $key_7cc3 = { 2f ac [2] 0b a2 [2] 20 8e [2] 0e ac [2] 1a b7 [2] 15 ad [2] 0b b0 [2] 09 b1 [2] 12 b7 [2] 0e b0 [2] 12 9f }

  condition:
    any of them
}