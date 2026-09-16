rule TTP_XOR_MULT_DOSStub_8391 {
  strings:
    $key_8391 = { d7 f9 [2] a3 e1 [2] e4 e3 [2] a3 f2 [2] ed fe [2] e1 f4 [2] f6 ff [2] ed b1 [2] d0 }

  condition:
    any of them
}