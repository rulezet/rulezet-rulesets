rule TTP_XOR_QUAD_CurrentVersionRun_94d6 {
  strings:
    $key_94d6 = { c7 b9 [2] e3 b7 [2] c8 9b [2] e6 b9 [2] f2 a2 [2] fd b8 [2] e3 a5 [2] e1 a4 [2] fa a2 [2] e6 a5 [2] fa 8a }

  condition:
    any of them
}