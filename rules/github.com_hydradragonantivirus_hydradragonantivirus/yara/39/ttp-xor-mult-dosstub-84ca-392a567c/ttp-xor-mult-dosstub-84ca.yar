rule TTP_XOR_MULT_DOSStub_84ca {
  strings:
    $key_84ca = { d0 a2 [2] a4 ba [2] e3 b8 [2] a4 a9 [2] ea a5 [2] e6 af [2] f1 a4 [2] ea ea [2] d7 }

  condition:
    any of them
}