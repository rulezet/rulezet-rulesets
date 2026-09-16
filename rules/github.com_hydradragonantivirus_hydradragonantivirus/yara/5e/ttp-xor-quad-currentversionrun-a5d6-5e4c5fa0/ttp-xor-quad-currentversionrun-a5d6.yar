rule TTP_XOR_QUAD_CurrentVersionRun_a5d6 {
  strings:
    $key_a5d6 = { f6 b9 [2] d2 b7 [2] f9 9b [2] d7 b9 [2] c3 a2 [2] cc b8 [2] d2 a5 [2] d0 a4 [2] cb a2 [2] d7 a5 [2] cb 8a }

  condition:
    any of them
}