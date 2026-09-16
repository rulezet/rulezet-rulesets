rule TTP_XOR_MULT_DOSStub_9689 {
  strings:
    $key_9689 = { c2 e1 [2] b6 f9 [2] f1 fb [2] b6 ea [2] f8 e6 [2] f4 ec [2] e3 e7 [2] f8 a9 [2] c5 }

  condition:
    any of them
}