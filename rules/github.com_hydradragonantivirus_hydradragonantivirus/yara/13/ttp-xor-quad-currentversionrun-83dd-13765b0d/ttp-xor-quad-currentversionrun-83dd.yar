rule TTP_XOR_QUAD_CurrentVersionRun_83dd {
  strings:
    $key_83dd = { d0 b2 [2] f4 bc [2] df 90 [2] f1 b2 [2] e5 a9 [2] ea b3 [2] f4 ae [2] f6 af [2] ed a9 [2] f1 ae [2] ed 81 }

  condition:
    any of them
}