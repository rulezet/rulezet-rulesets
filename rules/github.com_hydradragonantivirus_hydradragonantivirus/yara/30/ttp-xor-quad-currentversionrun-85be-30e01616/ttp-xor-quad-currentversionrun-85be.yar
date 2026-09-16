rule TTP_XOR_QUAD_CurrentVersionRun_85be {
  strings:
    $key_85be = { d6 d1 [2] f2 df [2] d9 f3 [2] f7 d1 [2] e3 ca [2] ec d0 [2] f2 cd [2] f0 cc [2] eb ca [2] f7 cd [2] eb e2 }

  condition:
    any of them
}