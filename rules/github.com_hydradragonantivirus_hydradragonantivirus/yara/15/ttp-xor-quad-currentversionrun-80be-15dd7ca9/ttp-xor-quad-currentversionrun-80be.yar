rule TTP_XOR_QUAD_CurrentVersionRun_80be {
  strings:
    $key_80be = { d3 d1 [2] f7 df [2] dc f3 [2] f2 d1 [2] e6 ca [2] e9 d0 [2] f7 cd [2] f5 cc [2] ee ca [2] f2 cd [2] ee e2 }

  condition:
    any of them
}