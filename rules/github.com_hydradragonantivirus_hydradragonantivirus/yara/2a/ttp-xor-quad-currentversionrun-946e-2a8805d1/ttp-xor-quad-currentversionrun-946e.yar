rule TTP_XOR_QUAD_CurrentVersionRun_946e {
  strings:
    $key_946e = { c7 01 [2] e3 0f [2] c8 23 [2] e6 01 [2] f2 1a [2] fd 00 [2] e3 1d [2] e1 1c [2] fa 1a [2] e6 1d [2] fa 32 }

  condition:
    any of them
}