rule TTP_XOR_QUAD_CurrentVersionRun_85f3 {
  strings:
    $key_85f3 = { d6 9c [2] f2 92 [2] d9 be [2] f7 9c [2] e3 87 [2] ec 9d [2] f2 80 [2] f0 81 [2] eb 87 [2] f7 80 [2] eb af }

  condition:
    any of them
}