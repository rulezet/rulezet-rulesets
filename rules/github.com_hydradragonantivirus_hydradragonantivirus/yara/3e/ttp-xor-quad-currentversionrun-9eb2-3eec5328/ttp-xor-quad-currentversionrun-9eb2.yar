rule TTP_XOR_QUAD_CurrentVersionRun_9eb2 {
  strings:
    $key_9eb2 = { cd dd [2] e9 d3 [2] c2 ff [2] ec dd [2] f8 c6 [2] f7 dc [2] e9 c1 [2] eb c0 [2] f0 c6 [2] ec c1 [2] f0 ee }

  condition:
    any of them
}