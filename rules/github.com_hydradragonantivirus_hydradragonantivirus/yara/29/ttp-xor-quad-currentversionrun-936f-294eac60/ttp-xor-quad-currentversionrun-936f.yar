rule TTP_XOR_QUAD_CurrentVersionRun_936f {
  strings:
    $key_936f = { c0 00 [2] e4 0e [2] cf 22 [2] e1 00 [2] f5 1b [2] fa 01 [2] e4 1c [2] e6 1d [2] fd 1b [2] e1 1c [2] fd 33 }

  condition:
    any of them
}