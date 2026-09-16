rule TTP_XOR_QUAD_CurrentVersionRun_9996 {
  strings:
    $key_9996 = { ca f9 [2] ee f7 [2] c5 db [2] eb f9 [2] ff e2 [2] f0 f8 [2] ee e5 [2] ec e4 [2] f7 e2 [2] eb e5 [2] f7 ca }

  condition:
    any of them
}