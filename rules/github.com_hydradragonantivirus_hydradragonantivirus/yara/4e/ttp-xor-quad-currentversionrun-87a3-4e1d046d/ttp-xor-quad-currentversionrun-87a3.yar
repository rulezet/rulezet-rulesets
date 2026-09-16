rule TTP_XOR_QUAD_CurrentVersionRun_87a3 {
  strings:
    $key_87a3 = { d4 cc [2] f0 c2 [2] db ee [2] f5 cc [2] e1 d7 [2] ee cd [2] f0 d0 [2] f2 d1 [2] e9 d7 [2] f5 d0 [2] e9 ff }

  condition:
    any of them
}