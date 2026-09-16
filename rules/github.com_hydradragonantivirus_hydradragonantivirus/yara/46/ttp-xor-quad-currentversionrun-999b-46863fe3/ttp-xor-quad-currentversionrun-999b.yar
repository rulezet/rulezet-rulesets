rule TTP_XOR_QUAD_CurrentVersionRun_999b {
  strings:
    $key_999b = { ca f4 [2] ee fa [2] c5 d6 [2] eb f4 [2] ff ef [2] f0 f5 [2] ee e8 [2] ec e9 [2] f7 ef [2] eb e8 [2] f7 c7 }

  condition:
    any of them
}