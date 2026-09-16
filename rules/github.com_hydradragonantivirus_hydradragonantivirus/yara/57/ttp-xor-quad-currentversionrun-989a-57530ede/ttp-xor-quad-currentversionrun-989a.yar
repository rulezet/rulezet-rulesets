rule TTP_XOR_QUAD_CurrentVersionRun_989a {
  strings:
    $key_989a = { cb f5 [2] ef fb [2] c4 d7 [2] ea f5 [2] fe ee [2] f1 f4 [2] ef e9 [2] ed e8 [2] f6 ee [2] ea e9 [2] f6 c6 }

  condition:
    any of them
}