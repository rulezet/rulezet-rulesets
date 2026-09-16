rule TTP_XOR_QUAD_CurrentVersionRun_85b3 {
  strings:
    $key_85b3 = { d6 dc [2] f2 d2 [2] d9 fe [2] f7 dc [2] e3 c7 [2] ec dd [2] f2 c0 [2] f0 c1 [2] eb c7 [2] f7 c0 [2] eb ef }

  condition:
    any of them
}