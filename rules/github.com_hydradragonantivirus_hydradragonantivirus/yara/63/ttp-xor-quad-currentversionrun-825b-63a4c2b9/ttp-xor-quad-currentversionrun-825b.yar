rule TTP_XOR_QUAD_CurrentVersionRun_825b {
  strings:
    $key_825b = { d1 34 [2] f5 3a [2] de 16 [2] f0 34 [2] e4 2f [2] eb 35 [2] f5 28 [2] f7 29 [2] ec 2f [2] f0 28 [2] ec 07 }

  condition:
    any of them
}