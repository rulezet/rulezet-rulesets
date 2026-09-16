rule TTP_XOR_QUAD_CurrentVersionRun_9bdc {
  strings:
    $key_9bdc = { c8 b3 [2] ec bd [2] c7 91 [2] e9 b3 [2] fd a8 [2] f2 b2 [2] ec af [2] ee ae [2] f5 a8 [2] e9 af [2] f5 80 }

  condition:
    any of them
}