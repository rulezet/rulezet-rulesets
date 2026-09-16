rule TTP_XOR_QUAD_CurrentVersionRun_83a8 {
  strings:
    $key_83a8 = { d0 c7 [2] f4 c9 [2] df e5 [2] f1 c7 [2] e5 dc [2] ea c6 [2] f4 db [2] f6 da [2] ed dc [2] f1 db [2] ed f4 }

  condition:
    any of them
}