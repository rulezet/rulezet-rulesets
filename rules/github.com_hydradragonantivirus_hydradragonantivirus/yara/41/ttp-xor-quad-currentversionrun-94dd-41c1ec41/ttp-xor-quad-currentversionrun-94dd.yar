rule TTP_XOR_QUAD_CurrentVersionRun_94dd {
  strings:
    $key_94dd = { c7 b2 [2] e3 bc [2] c8 90 [2] e6 b2 [2] f2 a9 [2] fd b3 [2] e3 ae [2] e1 af [2] fa a9 [2] e6 ae [2] fa 81 }

  condition:
    any of them
}