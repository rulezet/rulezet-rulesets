rule TTP_XOR_QUAD_CurrentVersionRun_85f7 {
  strings:
    $key_85f7 = { d6 98 [2] f2 96 [2] d9 ba [2] f7 98 [2] e3 83 [2] ec 99 [2] f2 84 [2] f0 85 [2] eb 83 [2] f7 84 [2] eb ab }

  condition:
    any of them
}