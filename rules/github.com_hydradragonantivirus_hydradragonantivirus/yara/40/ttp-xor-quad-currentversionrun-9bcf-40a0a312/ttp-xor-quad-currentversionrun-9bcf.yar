rule TTP_XOR_QUAD_CurrentVersionRun_9bcf {
  strings:
    $key_9bcf = { c8 a0 [2] ec ae [2] c7 82 [2] e9 a0 [2] fd bb [2] f2 a1 [2] ec bc [2] ee bd [2] f5 bb [2] e9 bc [2] f5 93 }

  condition:
    any of them
}