rule TTP_XOR_QUAD_CurrentVersionRun_8e83 {
  strings:
    $key_8e83 = { dd ec [2] f9 e2 [2] d2 ce [2] fc ec [2] e8 f7 [2] e7 ed [2] f9 f0 [2] fb f1 [2] e0 f7 [2] fc f0 [2] e0 df }

  condition:
    any of them
}