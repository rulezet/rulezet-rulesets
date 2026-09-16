rule TTP_XOR_QUAD_CurrentVersionRun_84cf {
  strings:
    $key_84cf = { d7 a0 [2] f3 ae [2] d8 82 [2] f6 a0 [2] e2 bb [2] ed a1 [2] f3 bc [2] f1 bd [2] ea bb [2] f6 bc [2] ea 93 }

  condition:
    any of them
}