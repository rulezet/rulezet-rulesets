rule TTP_XOR_QUAD_CurrentVersionRun_a596 {
  strings:
    $key_a596 = { f6 f9 [2] d2 f7 [2] f9 db [2] d7 f9 [2] c3 e2 [2] cc f8 [2] d2 e5 [2] d0 e4 [2] cb e2 [2] d7 e5 [2] cb ca }

  condition:
    any of them
}