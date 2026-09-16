rule TTP_XOR_QUAD_CurrentVersionRun_b7e1 {
  strings:
    $key_b7e1 = { e4 8e [2] c0 80 [2] eb ac [2] c5 8e [2] d1 95 [2] de 8f [2] c0 92 [2] c2 93 [2] d9 95 [2] c5 92 [2] d9 bd }

  condition:
    any of them
}