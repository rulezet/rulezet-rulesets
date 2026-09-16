rule TTP_XOR_QUAD_CurrentVersionRun_9451 {
  strings:
    $key_9451 = { c7 3e [2] e3 30 [2] c8 1c [2] e6 3e [2] f2 25 [2] fd 3f [2] e3 22 [2] e1 23 [2] fa 25 [2] e6 22 [2] fa 0d }

  condition:
    any of them
}