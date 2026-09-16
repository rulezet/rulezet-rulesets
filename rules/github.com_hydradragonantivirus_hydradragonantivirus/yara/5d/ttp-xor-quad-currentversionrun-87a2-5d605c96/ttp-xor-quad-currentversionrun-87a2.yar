rule TTP_XOR_QUAD_CurrentVersionRun_87a2 {
  strings:
    $key_87a2 = { d4 cd [2] f0 c3 [2] db ef [2] f5 cd [2] e1 d6 [2] ee cc [2] f0 d1 [2] f2 d0 [2] e9 d6 [2] f5 d1 [2] e9 fe }

  condition:
    any of them
}