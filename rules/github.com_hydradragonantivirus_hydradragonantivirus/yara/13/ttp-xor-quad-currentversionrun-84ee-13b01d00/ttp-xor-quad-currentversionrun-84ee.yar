rule TTP_XOR_QUAD_CurrentVersionRun_84ee {
  strings:
    $key_84ee = { d7 81 [2] f3 8f [2] d8 a3 [2] f6 81 [2] e2 9a [2] ed 80 [2] f3 9d [2] f1 9c [2] ea 9a [2] f6 9d [2] ea b2 }

  condition:
    any of them
}