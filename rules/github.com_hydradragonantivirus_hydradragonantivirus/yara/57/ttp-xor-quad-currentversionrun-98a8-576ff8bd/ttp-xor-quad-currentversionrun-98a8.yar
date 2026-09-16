rule TTP_XOR_QUAD_CurrentVersionRun_98a8 {
  strings:
    $key_98a8 = { cb c7 [2] ef c9 [2] c4 e5 [2] ea c7 [2] fe dc [2] f1 c6 [2] ef db [2] ed da [2] f6 dc [2] ea db [2] f6 f4 }

  condition:
    any of them
}