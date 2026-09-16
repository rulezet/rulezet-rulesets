rule TTP_XOR_QUAD_CurrentVersionRun_b71c {
  strings:
    $key_b71c = { e4 73 [2] c0 7d [2] eb 51 [2] c5 73 [2] d1 68 [2] de 72 [2] c0 6f [2] c2 6e [2] d9 68 [2] c5 6f [2] d9 40 }

  condition:
    any of them
}