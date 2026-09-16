rule TTP_XOR_QUAD_CurrentVersionRun_94ee {
  strings:
    $key_94ee = { c7 81 [2] e3 8f [2] c8 a3 [2] e6 81 [2] f2 9a [2] fd 80 [2] e3 9d [2] e1 9c [2] fa 9a [2] e6 9d [2] fa b2 }

  condition:
    any of them
}