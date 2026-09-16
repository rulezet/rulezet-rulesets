rule TTP_XOR_QUAD_CurrentVersionRun_9438 {
  strings:
    $key_9438 = { c7 57 [2] e3 59 [2] c8 75 [2] e6 57 [2] f2 4c [2] fd 56 [2] e3 4b [2] e1 4a [2] fa 4c [2] e6 4b [2] fa 64 }

  condition:
    any of them
}