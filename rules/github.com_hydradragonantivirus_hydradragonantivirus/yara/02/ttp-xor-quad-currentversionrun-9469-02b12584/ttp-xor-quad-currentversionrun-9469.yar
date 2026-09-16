rule TTP_XOR_QUAD_CurrentVersionRun_9469 {
  strings:
    $key_9469 = { c7 06 [2] e3 08 [2] c8 24 [2] e6 06 [2] f2 1d [2] fd 07 [2] e3 1a [2] e1 1b [2] fa 1d [2] e6 1a [2] fa 35 }

  condition:
    any of them
}