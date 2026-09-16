rule TTP_XOR_QUAD_CurrentVersionRun_98bb {
  strings:
    $key_98bb = { cb d4 [2] ef da [2] c4 f6 [2] ea d4 [2] fe cf [2] f1 d5 [2] ef c8 [2] ed c9 [2] f6 cf [2] ea c8 [2] f6 e7 }

  condition:
    any of them
}