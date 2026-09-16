rule TTP_XOR_QUAD_CurrentVersionRun_9987 {
  strings:
    $key_9987 = { ca e8 [2] ee e6 [2] c5 ca [2] eb e8 [2] ff f3 [2] f0 e9 [2] ee f4 [2] ec f5 [2] f7 f3 [2] eb f4 [2] f7 db }

  condition:
    any of them
}