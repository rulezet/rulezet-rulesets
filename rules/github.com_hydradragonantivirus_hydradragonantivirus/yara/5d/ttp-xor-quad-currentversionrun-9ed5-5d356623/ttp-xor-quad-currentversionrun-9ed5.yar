rule TTP_XOR_QUAD_CurrentVersionRun_9ed5 {
  strings:
    $key_9ed5 = { cd ba [2] e9 b4 [2] c2 98 [2] ec ba [2] f8 a1 [2] f7 bb [2] e9 a6 [2] eb a7 [2] f0 a1 [2] ec a6 [2] f0 89 }

  condition:
    any of them
}