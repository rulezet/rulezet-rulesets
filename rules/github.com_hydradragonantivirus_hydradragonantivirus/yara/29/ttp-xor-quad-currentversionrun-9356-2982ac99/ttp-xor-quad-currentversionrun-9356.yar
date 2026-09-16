rule TTP_XOR_QUAD_CurrentVersionRun_9356 {
  strings:
    $key_9356 = { c0 39 [2] e4 37 [2] cf 1b [2] e1 39 [2] f5 22 [2] fa 38 [2] e4 25 [2] e6 24 [2] fd 22 [2] e1 25 [2] fd 0a }

  condition:
    any of them
}