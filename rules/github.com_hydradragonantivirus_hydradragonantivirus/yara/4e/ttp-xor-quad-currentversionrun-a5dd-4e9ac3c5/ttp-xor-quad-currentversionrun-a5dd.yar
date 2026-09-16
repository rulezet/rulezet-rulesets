rule TTP_XOR_QUAD_CurrentVersionRun_a5dd {
  strings:
    $key_a5dd = { f6 b2 [2] d2 bc [2] f9 90 [2] d7 b2 [2] c3 a9 [2] cc b3 [2] d2 ae [2] d0 af [2] cb a9 [2] d7 ae [2] cb 81 }

  condition:
    any of them
}