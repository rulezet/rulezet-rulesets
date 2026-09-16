rule TTP_XOR_QUAD_CurrentVersionRun_9472 {
  strings:
    $key_9472 = { c7 1d [2] e3 13 [2] c8 3f [2] e6 1d [2] f2 06 [2] fd 1c [2] e3 01 [2] e1 00 [2] fa 06 [2] e6 01 [2] fa 2e }

  condition:
    any of them
}