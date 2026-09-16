rule TTP_XOR_QUAD_CurrentVersionRun_9683 {
  strings:
    $key_9683 = { c5 ec [2] e1 e2 [2] ca ce [2] e4 ec [2] f0 f7 [2] ff ed [2] e1 f0 [2] e3 f1 [2] f8 f7 [2] e4 f0 [2] f8 df }

  condition:
    any of them
}