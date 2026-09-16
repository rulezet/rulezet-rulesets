rule TTP_XOR_QUAD_CurrentVersionRun_a586 {
  strings:
    $key_a586 = { f6 e9 [2] d2 e7 [2] f9 cb [2] d7 e9 [2] c3 f2 [2] cc e8 [2] d2 f5 [2] d0 f4 [2] cb f2 [2] d7 f5 [2] cb da }

  condition:
    any of them
}