rule TTP_XOR_QUAD_CurrentVersionRun_9899 {
  strings:
    $key_9899 = { cb f6 [2] ef f8 [2] c4 d4 [2] ea f6 [2] fe ed [2] f1 f7 [2] ef ea [2] ed eb [2] f6 ed [2] ea ea [2] f6 c5 }

  condition:
    any of them
}