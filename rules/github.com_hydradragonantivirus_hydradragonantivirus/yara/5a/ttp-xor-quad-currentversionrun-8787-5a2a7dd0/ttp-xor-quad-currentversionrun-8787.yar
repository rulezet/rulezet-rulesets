rule TTP_XOR_QUAD_CurrentVersionRun_8787 {
  strings:
    $key_8787 = { d4 e8 [2] f0 e6 [2] db ca [2] f5 e8 [2] e1 f3 [2] ee e9 [2] f0 f4 [2] f2 f5 [2] e9 f3 [2] f5 f4 [2] e9 db }

  condition:
    any of them
}