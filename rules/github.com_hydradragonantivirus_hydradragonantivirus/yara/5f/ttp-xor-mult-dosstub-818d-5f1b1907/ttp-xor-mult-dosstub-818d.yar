rule TTP_XOR_MULT_DOSStub_818d {
  strings:
    $key_818d = { d5 e5 [2] a1 fd [2] e6 ff [2] a1 ee [2] ef e2 [2] e3 e8 [2] f4 e3 [2] ef ad [2] d2 }

  condition:
    any of them
}