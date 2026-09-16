rule TTP_XOR_QUAD_CurrentVersionRun_9446 {
  strings:
    $key_9446 = { c7 29 [2] e3 27 [2] c8 0b [2] e6 29 [2] f2 32 [2] fd 28 [2] e3 35 [2] e1 34 [2] fa 32 [2] e6 35 [2] fa 1a }

  condition:
    any of them
}