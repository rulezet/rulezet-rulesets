rule TTP_XOR_QUAD_CurrentVersionRun_9401 {
  strings:
    $key_9401 = { c7 6e [2] e3 60 [2] c8 4c [2] e6 6e [2] f2 75 [2] fd 6f [2] e3 72 [2] e1 73 [2] fa 75 [2] e6 72 [2] fa 5d }

  condition:
    any of them
}