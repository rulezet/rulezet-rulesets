rule TTP_XOR_QUAD_CurrentVersionRun_98aa {
  strings:
    $key_98aa = { cb c5 [2] ef cb [2] c4 e7 [2] ea c5 [2] fe de [2] f1 c4 [2] ef d9 [2] ed d8 [2] f6 de [2] ea d9 [2] f6 f6 }

  condition:
    any of them
}