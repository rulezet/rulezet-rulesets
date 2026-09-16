rule TTP_XOR_QUAD_CurrentVersionRun_9885 {
  strings:
    $key_9885 = { cb ea [2] ef e4 [2] c4 c8 [2] ea ea [2] fe f1 [2] f1 eb [2] ef f6 [2] ed f7 [2] f6 f1 [2] ea f6 [2] f6 d9 }

  condition:
    any of them
}