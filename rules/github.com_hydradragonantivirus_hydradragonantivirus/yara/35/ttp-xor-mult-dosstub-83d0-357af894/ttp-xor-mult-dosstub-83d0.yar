rule TTP_XOR_MULT_DOSStub_83d0 {
  strings:
    $key_83d0 = { d7 b8 [2] a3 a0 [2] e4 a2 [2] a3 b3 [2] ed bf [2] e1 b5 [2] f6 be [2] ed f0 [2] d0 }

  condition:
    any of them
}