rule TTP_XOR_QUAD_CurrentVersionRun_a5ce {
  strings:
    $key_a5ce = { f6 a1 [2] d2 af [2] f9 83 [2] d7 a1 [2] c3 ba [2] cc a0 [2] d2 bd [2] d0 bc [2] cb ba [2] d7 bd [2] cb 92 }

  condition:
    any of them
}