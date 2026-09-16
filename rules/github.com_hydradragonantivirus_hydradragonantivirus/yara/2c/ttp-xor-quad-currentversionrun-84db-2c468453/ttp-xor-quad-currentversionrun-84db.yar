rule TTP_XOR_QUAD_CurrentVersionRun_84db {
  strings:
    $key_84db = { d7 b4 [2] f3 ba [2] d8 96 [2] f6 b4 [2] e2 af [2] ed b5 [2] f3 a8 [2] f1 a9 [2] ea af [2] f6 a8 [2] ea 87 }

  condition:
    any of them
}