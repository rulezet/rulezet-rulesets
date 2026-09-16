rule TTP_XOR_QUAD_CurrentVersionRun_94da {
  strings:
    $key_94da = { c7 b5 [2] e3 bb [2] c8 97 [2] e6 b5 [2] f2 ae [2] fd b4 [2] e3 a9 [2] e1 a8 [2] fa ae [2] e6 a9 [2] fa 86 }

  condition:
    any of them
}