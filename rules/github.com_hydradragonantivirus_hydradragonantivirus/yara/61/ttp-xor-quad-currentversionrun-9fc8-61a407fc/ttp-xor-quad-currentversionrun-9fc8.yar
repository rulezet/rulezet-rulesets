rule TTP_XOR_QUAD_CurrentVersionRun_9fc8 {
  strings:
    $key_9fc8 = { cc a7 [2] e8 a9 [2] c3 85 [2] ed a7 [2] f9 bc [2] f6 a6 [2] e8 bb [2] ea ba [2] f1 bc [2] ed bb [2] f1 94 }

  condition:
    any of them
}