rule TTP_XOR_QUAD_CurrentVersionRun_98b8 {
  strings:
    $key_98b8 = { cb d7 [2] ef d9 [2] c4 f5 [2] ea d7 [2] fe cc [2] f1 d6 [2] ef cb [2] ed ca [2] f6 cc [2] ea cb [2] f6 e4 }

  condition:
    any of them
}