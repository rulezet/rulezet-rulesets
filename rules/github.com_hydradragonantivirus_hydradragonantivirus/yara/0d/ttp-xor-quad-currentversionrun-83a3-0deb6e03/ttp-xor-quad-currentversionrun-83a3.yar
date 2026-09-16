rule TTP_XOR_QUAD_CurrentVersionRun_83a3 {
  strings:
    $key_83a3 = { d0 cc [2] f4 c2 [2] df ee [2] f1 cc [2] e5 d7 [2] ea cd [2] f4 d0 [2] f6 d1 [2] ed d7 [2] f1 d0 [2] ed ff }

  condition:
    any of them
}