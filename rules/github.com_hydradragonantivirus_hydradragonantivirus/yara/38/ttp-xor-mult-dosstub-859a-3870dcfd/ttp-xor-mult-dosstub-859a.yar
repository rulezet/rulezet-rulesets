rule TTP_XOR_MULT_DOSStub_859a {
  strings:
    $key_859a = { d1 f2 [2] a5 ea [2] e2 e8 [2] a5 f9 [2] eb f5 [2] e7 ff [2] f0 f4 [2] eb ba [2] d6 }

  condition:
    any of them
}