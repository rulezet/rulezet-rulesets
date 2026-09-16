rule TTP_XOR_QUAD_CurrentVersionRun_9476 {
  strings:
    $key_9476 = { c7 19 [2] e3 17 [2] c8 3b [2] e6 19 [2] f2 02 [2] fd 18 [2] e3 05 [2] e1 04 [2] fa 02 [2] e6 05 [2] fa 2a }

  condition:
    any of them
}