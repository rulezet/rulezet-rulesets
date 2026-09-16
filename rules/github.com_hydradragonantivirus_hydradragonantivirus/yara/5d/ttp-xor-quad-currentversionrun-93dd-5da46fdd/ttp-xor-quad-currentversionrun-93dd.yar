rule TTP_XOR_QUAD_CurrentVersionRun_93dd {
  strings:
    $key_93dd = { c0 b2 [2] e4 bc [2] cf 90 [2] e1 b2 [2] f5 a9 [2] fa b3 [2] e4 ae [2] e6 af [2] fd a9 [2] e1 ae [2] fd 81 }

  condition:
    any of them
}