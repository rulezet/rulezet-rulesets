rule TTP_XOR_QUAD_CurrentVersionRun_9697 {
  strings:
    $key_9697 = { c5 f8 [2] e1 f6 [2] ca da [2] e4 f8 [2] f0 e3 [2] ff f9 [2] e1 e4 [2] e3 e5 [2] f8 e3 [2] e4 e4 [2] f8 cb }

  condition:
    any of them
}