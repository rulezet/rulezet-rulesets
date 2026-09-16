rule TTP_XOR_QUAD_CurrentVersionRun_9988 {
  strings:
    $key_9988 = { ca e7 [2] ee e9 [2] c5 c5 [2] eb e7 [2] ff fc [2] f0 e6 [2] ee fb [2] ec fa [2] f7 fc [2] eb fb [2] f7 d4 }

  condition:
    any of them
}