rule TTP_XOR_QUAD_CurrentVersionRun_a5a8 {
  strings:
    $key_a5a8 = { f6 c7 [2] d2 c9 [2] f9 e5 [2] d7 c7 [2] c3 dc [2] cc c6 [2] d2 db [2] d0 da [2] cb dc [2] d7 db [2] cb f4 }

  condition:
    any of them
}