rule TTP_XOR_MULT_DOSStub_9691 {
  strings:
    $key_9691 = { c2 f9 [2] b6 e1 [2] f1 e3 [2] b6 f2 [2] f8 fe [2] f4 f4 [2] e3 ff [2] f8 b1 [2] c5 }

  condition:
    any of them
}