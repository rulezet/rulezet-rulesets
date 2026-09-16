rule TTP_XOR_QUAD_CurrentVersionRun_a5b4 {
  strings:
    $key_a5b4 = { f6 db [2] d2 d5 [2] f9 f9 [2] d7 db [2] c3 c0 [2] cc da [2] d2 c7 [2] d0 c6 [2] cb c0 [2] d7 c7 [2] cb e8 }

  condition:
    any of them
}