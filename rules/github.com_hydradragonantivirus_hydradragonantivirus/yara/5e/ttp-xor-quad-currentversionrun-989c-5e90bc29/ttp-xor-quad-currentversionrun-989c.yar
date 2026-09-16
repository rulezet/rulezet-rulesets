rule TTP_XOR_QUAD_CurrentVersionRun_989c {
  strings:
    $key_989c = { cb f3 [2] ef fd [2] c4 d1 [2] ea f3 [2] fe e8 [2] f1 f2 [2] ef ef [2] ed ee [2] f6 e8 [2] ea ef [2] f6 c0 }

  condition:
    any of them
}