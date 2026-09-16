rule TTP_XOR_QUAD_CurrentVersionRun_9097 {
  strings:
    $key_9097 = { c3 f8 [2] e7 f6 [2] cc da [2] e2 f8 [2] f6 e3 [2] f9 f9 [2] e7 e4 [2] e5 e5 [2] fe e3 [2] e2 e4 [2] fe cb }

  condition:
    any of them
}