rule TTP_XOR_QUAD_CurrentVersionRun_989f {
  strings:
    $key_989f = { cb f0 [2] ef fe [2] c4 d2 [2] ea f0 [2] fe eb [2] f1 f1 [2] ef ec [2] ed ed [2] f6 eb [2] ea ec [2] f6 c3 }

  condition:
    any of them
}