rule TTP_XOR_QUAD_CurrentVersionRun_94bf {
  strings:
    $key_94bf = { c7 d0 [2] e3 de [2] c8 f2 [2] e6 d0 [2] f2 cb [2] fd d1 [2] e3 cc [2] e1 cd [2] fa cb [2] e6 cc [2] fa e3 }

  condition:
    any of them
}