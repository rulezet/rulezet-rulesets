rule TTP_XOR_QUAD_CurrentVersionRun_946f {
  strings:
    $key_946f = { c7 00 [2] e3 0e [2] c8 22 [2] e6 00 [2] f2 1b [2] fd 01 [2] e3 1c [2] e1 1d [2] fa 1b [2] e6 1c [2] fa 33 }

  condition:
    any of them
}