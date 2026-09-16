rule TTP_XOR_MULT_DOSStub_8488 {
  strings:
    $key_8488 = { d0 e0 [2] a4 f8 [2] e3 fa [2] a4 eb [2] ea e7 [2] e6 ed [2] f1 e6 [2] ea a8 [2] d7 }

  condition:
    any of them
}