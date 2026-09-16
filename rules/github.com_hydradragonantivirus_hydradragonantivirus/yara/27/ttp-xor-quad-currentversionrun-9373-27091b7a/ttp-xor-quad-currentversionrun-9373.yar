rule TTP_XOR_QUAD_CurrentVersionRun_9373 {
  strings:
    $key_9373 = { c0 1c [2] e4 12 [2] cf 3e [2] e1 1c [2] f5 07 [2] fa 1d [2] e4 00 [2] e6 01 [2] fd 07 [2] e1 00 [2] fd 2f }

  condition:
    any of them
}