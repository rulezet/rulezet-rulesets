rule TTP_XOR_QUAD_CurrentVersionRun_98a7 {
  strings:
    $key_98a7 = { cb c8 [2] ef c6 [2] c4 ea [2] ea c8 [2] fe d3 [2] f1 c9 [2] ef d4 [2] ed d5 [2] f6 d3 [2] ea d4 [2] f6 fb }

  condition:
    any of them
}