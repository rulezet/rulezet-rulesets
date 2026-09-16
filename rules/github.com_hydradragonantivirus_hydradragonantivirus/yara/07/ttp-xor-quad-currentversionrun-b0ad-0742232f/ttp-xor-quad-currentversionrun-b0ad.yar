rule TTP_XOR_QUAD_CurrentVersionRun_b0ad {
  strings:
    $key_b0ad = { e3 c2 [2] c7 cc [2] ec e0 [2] c2 c2 [2] d6 d9 [2] d9 c3 [2] c7 de [2] c5 df [2] de d9 [2] c2 de [2] de f1 }

  condition:
    any of them
}