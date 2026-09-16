rule TTP_XOR_QUAD_CurrentVersionRun_b710 {
  strings:
    $key_b710 = { e4 7f [2] c0 71 [2] eb 5d [2] c5 7f [2] d1 64 [2] de 7e [2] c0 63 [2] c2 62 [2] d9 64 [2] c5 63 [2] d9 4c }

  condition:
    any of them
}