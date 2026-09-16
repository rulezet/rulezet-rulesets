rule TTP_XOR_QUAD_CurrentVersionRun_9884 {
  strings:
    $key_9884 = { cb eb [2] ef e5 [2] c4 c9 [2] ea eb [2] fe f0 [2] f1 ea [2] ef f7 [2] ed f6 [2] f6 f0 [2] ea f7 [2] f6 d8 }

  condition:
    any of them
}