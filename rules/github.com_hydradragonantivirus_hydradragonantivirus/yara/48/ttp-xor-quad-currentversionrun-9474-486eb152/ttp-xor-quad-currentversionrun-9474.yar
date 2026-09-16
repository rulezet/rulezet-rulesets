rule TTP_XOR_QUAD_CurrentVersionRun_9474 {
  strings:
    $key_9474 = { c7 1b [2] e3 15 [2] c8 39 [2] e6 1b [2] f2 00 [2] fd 1a [2] e3 07 [2] e1 06 [2] fa 00 [2] e6 07 [2] fa 28 }

  condition:
    any of them
}