rule TTP_XOR_QUAD_CurrentVersionRun_9426 {
  strings:
    $key_9426 = { c7 49 [2] e3 47 [2] c8 6b [2] e6 49 [2] f2 52 [2] fd 48 [2] e3 55 [2] e1 54 [2] fa 52 [2] e6 55 [2] fa 7a }

  condition:
    any of them
}