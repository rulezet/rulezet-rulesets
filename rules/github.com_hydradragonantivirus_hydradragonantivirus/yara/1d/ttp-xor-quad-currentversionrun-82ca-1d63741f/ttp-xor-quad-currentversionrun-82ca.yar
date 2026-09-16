rule TTP_XOR_QUAD_CurrentVersionRun_82ca {
  strings:
    $key_82ca = { d1 a5 [2] f5 ab [2] de 87 [2] f0 a5 [2] e4 be [2] eb a4 [2] f5 b9 [2] f7 b8 [2] ec be [2] f0 b9 [2] ec 96 }

  condition:
    any of them
}