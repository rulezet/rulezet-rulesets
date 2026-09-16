rule TTP_XOR_QUAD_CurrentVersionRun_9bdd {
  strings:
    $key_9bdd = { c8 b2 [2] ec bc [2] c7 90 [2] e9 b2 [2] fd a9 [2] f2 b3 [2] ec ae [2] ee af [2] f5 a9 [2] e9 ae [2] f5 81 }

  condition:
    any of them
}