rule TTP_XOR_QUAD_CurrentVersionRun_9482 {
  strings:
    $key_9482 = { c7 ed [2] e3 e3 [2] c8 cf [2] e6 ed [2] f2 f6 [2] fd ec [2] e3 f1 [2] e1 f0 [2] fa f6 [2] e6 f1 [2] fa de }

  condition:
    any of them
}