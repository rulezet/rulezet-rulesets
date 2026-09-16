rule TTP_XOR_QUAD_CurrentVersionRun_9436 {
  strings:
    $key_9436 = { c7 59 [2] e3 57 [2] c8 7b [2] e6 59 [2] f2 42 [2] fd 58 [2] e3 45 [2] e1 44 [2] fa 42 [2] e6 45 [2] fa 6a }

  condition:
    any of them
}