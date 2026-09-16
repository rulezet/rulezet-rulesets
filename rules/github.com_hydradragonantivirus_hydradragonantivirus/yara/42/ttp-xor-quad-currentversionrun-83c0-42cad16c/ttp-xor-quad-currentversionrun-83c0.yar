rule TTP_XOR_QUAD_CurrentVersionRun_83c0 {
  strings:
    $key_83c0 = { d0 af [2] f4 a1 [2] df 8d [2] f1 af [2] e5 b4 [2] ea ae [2] f4 b3 [2] f6 b2 [2] ed b4 [2] f1 b3 [2] ed 9c }

  condition:
    any of them
}