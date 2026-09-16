rule TTP_XOR_MULT_DOSStub_84c1 {
  strings:
    $key_84c1 = { d0 a9 [2] a4 b1 [2] e3 b3 [2] a4 a2 [2] ea ae [2] e6 a4 [2] f1 af [2] ea e1 [2] d7 }

  condition:
    any of them
}