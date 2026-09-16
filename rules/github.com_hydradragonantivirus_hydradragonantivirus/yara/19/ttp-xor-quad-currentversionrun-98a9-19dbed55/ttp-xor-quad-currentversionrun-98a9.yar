rule TTP_XOR_QUAD_CurrentVersionRun_98a9 {
  strings:
    $key_98a9 = { cb c6 [2] ef c8 [2] c4 e4 [2] ea c6 [2] fe dd [2] f1 c7 [2] ef da [2] ed db [2] f6 dd [2] ea da [2] f6 f5 }

  condition:
    any of them
}