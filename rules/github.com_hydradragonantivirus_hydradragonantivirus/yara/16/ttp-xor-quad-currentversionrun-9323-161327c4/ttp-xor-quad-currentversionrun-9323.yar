rule TTP_XOR_QUAD_CurrentVersionRun_9323 {
  strings:
    $key_9323 = { c0 4c [2] e4 42 [2] cf 6e [2] e1 4c [2] f5 57 [2] fa 4d [2] e4 50 [2] e6 51 [2] fd 57 [2] e1 50 [2] fd 7f }

  condition:
    any of them
}