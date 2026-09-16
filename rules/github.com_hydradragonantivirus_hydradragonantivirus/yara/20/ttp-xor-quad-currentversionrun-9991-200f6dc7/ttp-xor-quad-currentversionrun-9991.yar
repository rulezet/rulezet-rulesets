rule TTP_XOR_QUAD_CurrentVersionRun_9991 {
  strings:
    $key_9991 = { ca fe [2] ee f0 [2] c5 dc [2] eb fe [2] ff e5 [2] f0 ff [2] ee e2 [2] ec e3 [2] f7 e5 [2] eb e2 [2] f7 cd }

  condition:
    any of them
}