rule TTP_XOR_QUAD_CurrentVersionRun_9397 {
  strings:
    $key_9397 = { c0 f8 [2] e4 f6 [2] cf da [2] e1 f8 [2] f5 e3 [2] fa f9 [2] e4 e4 [2] e6 e5 [2] fd e3 [2] e1 e4 [2] fd cb }

  condition:
    any of them
}