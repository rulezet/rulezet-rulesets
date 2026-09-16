rule TTP_XOR_QUAD_CurrentVersionRun_b730 {
  strings:
    $key_b730 = { e4 5f [2] c0 51 [2] eb 7d [2] c5 5f [2] d1 44 [2] de 5e [2] c0 43 [2] c2 42 [2] d9 44 [2] c5 43 [2] d9 6c }

  condition:
    any of them
}