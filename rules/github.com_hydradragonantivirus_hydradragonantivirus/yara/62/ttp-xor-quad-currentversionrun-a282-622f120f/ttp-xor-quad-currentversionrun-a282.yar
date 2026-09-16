rule TTP_XOR_QUAD_CurrentVersionRun_a282 {
  strings:
    $key_a282 = { f1 ed [2] d5 e3 [2] fe cf [2] d0 ed [2] c4 f6 [2] cb ec [2] d5 f1 [2] d7 f0 [2] cc f6 [2] d0 f1 [2] cc de }

  condition:
    any of them
}