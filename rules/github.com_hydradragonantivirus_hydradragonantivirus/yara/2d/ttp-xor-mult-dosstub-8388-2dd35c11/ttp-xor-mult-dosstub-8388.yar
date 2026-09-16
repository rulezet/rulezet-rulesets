rule TTP_XOR_MULT_DOSStub_8388 {
  strings:
    $key_8388 = { d7 e0 [2] a3 f8 [2] e4 fa [2] a3 eb [2] ed e7 [2] e1 ed [2] f6 e6 [2] ed a8 [2] d0 }

  condition:
    any of them
}