rule TTP_XOR_QUAD_CurrentVersionRun_9375 {
  strings:
    $key_9375 = { c0 1a [2] e4 14 [2] cf 38 [2] e1 1a [2] f5 01 [2] fa 1b [2] e4 06 [2] e6 07 [2] fd 01 [2] e1 06 [2] fd 29 }

  condition:
    any of them
}