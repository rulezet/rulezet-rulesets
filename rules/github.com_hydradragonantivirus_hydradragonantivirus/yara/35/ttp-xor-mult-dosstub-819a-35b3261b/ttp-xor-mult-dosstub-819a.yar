rule TTP_XOR_MULT_DOSStub_819a {
  strings:
    $key_819a = { d5 f2 [2] a1 ea [2] e6 e8 [2] a1 f9 [2] ef f5 [2] e3 ff [2] f4 f4 [2] ef ba [2] d2 }

  condition:
    any of them
}