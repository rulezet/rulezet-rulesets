rule TTP_XOR_QUAD_CurrentVersionRun_9445 {
  strings:
    $key_9445 = { c7 2a [2] e3 24 [2] c8 08 [2] e6 2a [2] f2 31 [2] fd 2b [2] e3 36 [2] e1 37 [2] fa 31 [2] e6 36 [2] fa 19 }

  condition:
    any of them
}