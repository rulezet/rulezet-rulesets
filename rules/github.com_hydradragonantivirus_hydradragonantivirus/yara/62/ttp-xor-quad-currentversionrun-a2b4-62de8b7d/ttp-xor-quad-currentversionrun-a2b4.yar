rule TTP_XOR_QUAD_CurrentVersionRun_a2b4 {
  strings:
    $key_a2b4 = { f1 db [2] d5 d5 [2] fe f9 [2] d0 db [2] c4 c0 [2] cb da [2] d5 c7 [2] d7 c6 [2] cc c0 [2] d0 c7 [2] cc e8 }

  condition:
    any of them
}