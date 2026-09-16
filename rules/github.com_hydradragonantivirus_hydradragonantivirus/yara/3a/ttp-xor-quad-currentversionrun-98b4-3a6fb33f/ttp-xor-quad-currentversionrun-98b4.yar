rule TTP_XOR_QUAD_CurrentVersionRun_98b4 {
  strings:
    $key_98b4 = { cb db [2] ef d5 [2] c4 f9 [2] ea db [2] fe c0 [2] f1 da [2] ef c7 [2] ed c6 [2] f6 c0 [2] ea c7 [2] f6 e8 }

  condition:
    any of them
}