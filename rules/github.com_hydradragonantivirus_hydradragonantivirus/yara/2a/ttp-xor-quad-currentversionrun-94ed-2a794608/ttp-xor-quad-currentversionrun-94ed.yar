rule TTP_XOR_QUAD_CurrentVersionRun_94ed {
  strings:
    $key_94ed = { c7 82 [2] e3 8c [2] c8 a0 [2] e6 82 [2] f2 99 [2] fd 83 [2] e3 9e [2] e1 9f [2] fa 99 [2] e6 9e [2] fa b1 }

  condition:
    any of them
}