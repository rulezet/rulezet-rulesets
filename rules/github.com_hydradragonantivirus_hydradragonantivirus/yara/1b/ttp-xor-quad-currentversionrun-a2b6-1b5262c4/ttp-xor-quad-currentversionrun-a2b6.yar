rule TTP_XOR_QUAD_CurrentVersionRun_a2b6 {
  strings:
    $key_a2b6 = { f1 d9 [2] d5 d7 [2] fe fb [2] d0 d9 [2] c4 c2 [2] cb d8 [2] d5 c5 [2] d7 c4 [2] cc c2 [2] d0 c5 [2] cc ea }

  condition:
    any of them
}