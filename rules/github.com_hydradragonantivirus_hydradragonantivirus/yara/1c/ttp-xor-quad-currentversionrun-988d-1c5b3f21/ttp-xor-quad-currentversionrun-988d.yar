rule TTP_XOR_QUAD_CurrentVersionRun_988d {
  strings:
    $key_988d = { cb e2 [2] ef ec [2] c4 c0 [2] ea e2 [2] fe f9 [2] f1 e3 [2] ef fe [2] ed ff [2] f6 f9 [2] ea fe [2] f6 d1 }

  condition:
    any of them
}