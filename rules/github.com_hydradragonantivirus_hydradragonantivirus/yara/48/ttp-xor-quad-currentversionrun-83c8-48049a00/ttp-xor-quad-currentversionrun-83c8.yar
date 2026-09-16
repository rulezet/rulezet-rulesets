rule TTP_XOR_QUAD_CurrentVersionRun_83c8 {
  strings:
    $key_83c8 = { d0 a7 [2] f4 a9 [2] df 85 [2] f1 a7 [2] e5 bc [2] ea a6 [2] f4 bb [2] f6 ba [2] ed bc [2] f1 bb [2] ed 94 }

  condition:
    any of them
}