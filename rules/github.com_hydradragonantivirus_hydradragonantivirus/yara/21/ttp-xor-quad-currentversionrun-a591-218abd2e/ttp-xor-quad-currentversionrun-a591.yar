rule TTP_XOR_QUAD_CurrentVersionRun_a591 {
  strings:
    $key_a591 = { f6 fe [2] d2 f0 [2] f9 dc [2] d7 fe [2] c3 e5 [2] cc ff [2] d2 e2 [2] d0 e3 [2] cb e5 [2] d7 e2 [2] cb cd }

  condition:
    any of them
}