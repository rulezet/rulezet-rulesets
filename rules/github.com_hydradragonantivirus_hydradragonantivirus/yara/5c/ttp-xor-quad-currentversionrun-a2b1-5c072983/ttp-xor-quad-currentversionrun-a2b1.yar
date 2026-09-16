rule TTP_XOR_QUAD_CurrentVersionRun_a2b1 {
  strings:
    $key_a2b1 = { f1 de [2] d5 d0 [2] fe fc [2] d0 de [2] c4 c5 [2] cb df [2] d5 c2 [2] d7 c3 [2] cc c5 [2] d0 c2 [2] cc ed }

  condition:
    any of them
}