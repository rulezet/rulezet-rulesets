rule TTP_XOR_QUAD_CurrentVersionRun_9351 {
  strings:
    $key_9351 = { c0 3e [2] e4 30 [2] cf 1c [2] e1 3e [2] f5 25 [2] fa 3f [2] e4 22 [2] e6 23 [2] fd 25 [2] e1 22 [2] fd 0d }

  condition:
    any of them
}