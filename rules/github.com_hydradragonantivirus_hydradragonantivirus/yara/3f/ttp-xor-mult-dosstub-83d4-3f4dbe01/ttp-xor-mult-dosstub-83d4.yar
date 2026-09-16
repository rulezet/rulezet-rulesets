rule TTP_XOR_MULT_DOSStub_83d4 {
  strings:
    $key_83d4 = { d7 bc [2] a3 a4 [2] e4 a6 [2] a3 b7 [2] ed bb [2] e1 b1 [2] f6 ba [2] ed f4 [2] d0 }

  condition:
    any of them
}