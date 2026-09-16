rule TTP_XOR_QUAD_CurrentVersionRun_b0f1 {
  strings:
    $key_b0f1 = { e3 9e [2] c7 90 [2] ec bc [2] c2 9e [2] d6 85 [2] d9 9f [2] c7 82 [2] c5 83 [2] de 85 [2] c2 82 [2] de ad }

  condition:
    any of them
}