rule TTP_XOR_QUAD_CurrentVersionRun_98b0 {
  strings:
    $key_98b0 = { cb df [2] ef d1 [2] c4 fd [2] ea df [2] fe c4 [2] f1 de [2] ef c3 [2] ed c2 [2] f6 c4 [2] ea c3 [2] f6 ec }

  condition:
    any of them
}