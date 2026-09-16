rule TTP_XOR_QUAD_CurrentVersionRun_86ff {
  strings:
    $key_86ff = { d5 90 [2] f1 9e [2] da b2 [2] f4 90 [2] e0 8b [2] ef 91 [2] f1 8c [2] f3 8d [2] e8 8b [2] f4 8c [2] e8 a3 }

  condition:
    any of them
}