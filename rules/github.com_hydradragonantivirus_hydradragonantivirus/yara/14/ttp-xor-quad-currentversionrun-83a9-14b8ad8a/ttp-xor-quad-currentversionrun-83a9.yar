rule TTP_XOR_QUAD_CurrentVersionRun_83a9 {
  strings:
    $key_83a9 = { d0 c6 [2] f4 c8 [2] df e4 [2] f1 c6 [2] e5 dd [2] ea c7 [2] f4 da [2] f6 db [2] ed dd [2] f1 da [2] ed f5 }

  condition:
    any of them
}