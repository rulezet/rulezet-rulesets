rule TTP_XOR_QUAD_CurrentVersionRun_b776 {
  strings:
    $key_b776 = { e4 19 [2] c0 17 [2] eb 3b [2] c5 19 [2] d1 02 [2] de 18 [2] c0 05 [2] c2 04 [2] d9 02 [2] c5 05 [2] d9 2a }

  condition:
    any of them
}