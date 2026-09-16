rule TTP_XOR_QUAD_CurrentVersionRun_a2b3 {
  strings:
    $key_a2b3 = { f1 dc [2] d5 d2 [2] fe fe [2] d0 dc [2] c4 c7 [2] cb dd [2] d5 c0 [2] d7 c1 [2] cc c7 [2] d0 c0 [2] cc ef }

  condition:
    any of them
}