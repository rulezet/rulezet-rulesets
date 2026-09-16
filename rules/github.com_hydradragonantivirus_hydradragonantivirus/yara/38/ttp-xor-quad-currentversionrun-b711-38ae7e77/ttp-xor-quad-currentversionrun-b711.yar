rule TTP_XOR_QUAD_CurrentVersionRun_b711 {
  strings:
    $key_b711 = { e4 7e [2] c0 70 [2] eb 5c [2] c5 7e [2] d1 65 [2] de 7f [2] c0 62 [2] c2 63 [2] d9 65 [2] c5 62 [2] d9 4d }

  condition:
    any of them
}