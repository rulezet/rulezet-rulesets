rule TTP_XOR_MULT_DOSStub_83d9 {
  strings:
    $key_83d9 = { d7 b1 [2] a3 a9 [2] e4 ab [2] a3 ba [2] ed b6 [2] e1 bc [2] f6 b7 [2] ed f9 [2] d0 }

  condition:
    any of them
}