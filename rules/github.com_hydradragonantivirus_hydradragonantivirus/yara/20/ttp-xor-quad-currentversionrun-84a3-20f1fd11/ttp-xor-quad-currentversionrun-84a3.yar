rule TTP_XOR_QUAD_CurrentVersionRun_84a3 {
  strings:
    $key_84a3 = { d7 cc [2] f3 c2 [2] d8 ee [2] f6 cc [2] e2 d7 [2] ed cd [2] f3 d0 [2] f1 d1 [2] ea d7 [2] f6 d0 [2] ea ff }

  condition:
    any of them
}