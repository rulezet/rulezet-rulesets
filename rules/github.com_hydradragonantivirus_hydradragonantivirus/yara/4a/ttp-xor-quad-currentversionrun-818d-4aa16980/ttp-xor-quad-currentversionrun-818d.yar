rule TTP_XOR_QUAD_CurrentVersionRun_818d {
  strings:
    $key_818d = { d2 e2 [2] f6 ec [2] dd c0 [2] f3 e2 [2] e7 f9 [2] e8 e3 [2] f6 fe [2] f4 ff [2] ef f9 [2] f3 fe [2] ef d1 }

  condition:
    any of them
}