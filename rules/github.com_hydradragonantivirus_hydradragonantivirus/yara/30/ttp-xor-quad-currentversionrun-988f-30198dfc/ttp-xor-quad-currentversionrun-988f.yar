rule TTP_XOR_QUAD_CurrentVersionRun_988f {
  strings:
    $key_988f = { cb e0 [2] ef ee [2] c4 c2 [2] ea e0 [2] fe fb [2] f1 e1 [2] ef fc [2] ed fd [2] f6 fb [2] ea fc [2] f6 d3 }

  condition:
    any of them
}