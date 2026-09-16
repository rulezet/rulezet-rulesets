rule TTP_XOR_QUAD_CurrentVersionRun_83a2 {
  strings:
    $key_83a2 = { d0 cd [2] f4 c3 [2] df ef [2] f1 cd [2] e5 d6 [2] ea cc [2] f4 d1 [2] f6 d0 [2] ed d6 [2] f1 d1 [2] ed fe }

  condition:
    any of them
}