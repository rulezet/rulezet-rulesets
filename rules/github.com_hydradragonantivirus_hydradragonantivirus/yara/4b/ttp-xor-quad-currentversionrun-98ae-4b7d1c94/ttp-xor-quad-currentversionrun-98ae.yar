rule TTP_XOR_QUAD_CurrentVersionRun_98ae {
  strings:
    $key_98ae = { cb c1 [2] ef cf [2] c4 e3 [2] ea c1 [2] fe da [2] f1 c0 [2] ef dd [2] ed dc [2] f6 da [2] ea dd [2] f6 f2 }

  condition:
    any of them
}