rule TTP_XOR_QUAD_CurrentVersionRun_a597 {
  strings:
    $key_a597 = { f6 f8 [2] d2 f6 [2] f9 da [2] d7 f8 [2] c3 e3 [2] cc f9 [2] d2 e4 [2] d0 e5 [2] cb e3 [2] d7 e4 [2] cb cb }

  condition:
    any of them
}