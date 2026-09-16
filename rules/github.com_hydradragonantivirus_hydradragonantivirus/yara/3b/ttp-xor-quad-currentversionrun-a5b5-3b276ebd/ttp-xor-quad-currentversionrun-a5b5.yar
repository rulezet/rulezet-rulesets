rule TTP_XOR_QUAD_CurrentVersionRun_a5b5 {
  strings:
    $key_a5b5 = { f6 da [2] d2 d4 [2] f9 f8 [2] d7 da [2] c3 c1 [2] cc db [2] d2 c6 [2] d0 c7 [2] cb c1 [2] d7 c6 [2] cb e9 }

  condition:
    any of them
}