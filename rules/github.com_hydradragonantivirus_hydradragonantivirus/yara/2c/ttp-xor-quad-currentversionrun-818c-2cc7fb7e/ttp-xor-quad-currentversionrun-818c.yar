rule TTP_XOR_QUAD_CurrentVersionRun_818c {
  strings:
    $key_818c = { d2 e3 [2] f6 ed [2] dd c1 [2] f3 e3 [2] e7 f8 [2] e8 e2 [2] f6 ff [2] f4 fe [2] ef f8 [2] f3 ff [2] ef d0 }

  condition:
    any of them
}