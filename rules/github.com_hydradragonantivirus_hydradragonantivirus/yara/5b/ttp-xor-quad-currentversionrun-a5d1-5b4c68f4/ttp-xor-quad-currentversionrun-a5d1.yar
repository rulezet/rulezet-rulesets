rule TTP_XOR_QUAD_CurrentVersionRun_a5d1 {
  strings:
    $key_a5d1 = { f6 be [2] d2 b0 [2] f9 9c [2] d7 be [2] c3 a5 [2] cc bf [2] d2 a2 [2] d0 a3 [2] cb a5 [2] d7 a2 [2] cb 8d }

  condition:
    any of them
}