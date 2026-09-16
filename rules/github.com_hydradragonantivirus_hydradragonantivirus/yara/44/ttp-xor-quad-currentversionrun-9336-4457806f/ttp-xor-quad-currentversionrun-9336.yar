rule TTP_XOR_QUAD_CurrentVersionRun_9336 {
  strings:
    $key_9336 = { c0 59 [2] e4 57 [2] cf 7b [2] e1 59 [2] f5 42 [2] fa 58 [2] e4 45 [2] e6 44 [2] fd 42 [2] e1 45 [2] fd 6a }

  condition:
    any of them
}