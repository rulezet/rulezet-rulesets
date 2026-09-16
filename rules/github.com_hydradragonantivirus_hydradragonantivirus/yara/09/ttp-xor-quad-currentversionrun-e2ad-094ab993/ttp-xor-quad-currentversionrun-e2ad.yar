rule TTP_XOR_QUAD_CurrentVersionRun_e2ad {
  strings:
    $key_e2ad = { b1 c2 [2] 95 cc [2] be e0 [2] 90 c2 [2] 84 d9 [2] 8b c3 [2] 95 de [2] 97 df [2] 8c d9 [2] 90 de [2] 8c f1 }

  condition:
    any of them
}