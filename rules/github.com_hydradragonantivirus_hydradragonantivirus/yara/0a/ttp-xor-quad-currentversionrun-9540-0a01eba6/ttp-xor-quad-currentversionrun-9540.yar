rule TTP_XOR_QUAD_CurrentVersionRun_9540 {
  strings:
    $key_9540 = { c6 2f [2] e2 21 [2] c9 0d [2] e7 2f [2] f3 34 [2] fc 2e [2] e2 33 [2] e0 32 [2] fb 34 [2] e7 33 [2] fb 1c }

  condition:
    any of them
}