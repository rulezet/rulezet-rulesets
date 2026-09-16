rule TTP_XOR_QUAD_CurrentVersionRun_9441 {
  strings:
    $key_9441 = { c7 2e [2] e3 20 [2] c8 0c [2] e6 2e [2] f2 35 [2] fd 2f [2] e3 32 [2] e1 33 [2] fa 35 [2] e6 32 [2] fa 1d }

  condition:
    any of them
}