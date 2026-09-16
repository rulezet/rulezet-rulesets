rule TTP_XOR_QUAD_CurrentVersionRun_94f4 {
  strings:
    $key_94f4 = { c7 9b [2] e3 95 [2] c8 b9 [2] e6 9b [2] f2 80 [2] fd 9a [2] e3 87 [2] e1 86 [2] fa 80 [2] e6 87 [2] fa a8 }

  condition:
    any of them
}