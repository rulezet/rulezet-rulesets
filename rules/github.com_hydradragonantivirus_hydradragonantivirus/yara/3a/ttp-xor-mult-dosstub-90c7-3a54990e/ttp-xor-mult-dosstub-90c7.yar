rule TTP_XOR_MULT_DOSStub_90c7 {
  strings:
    $key_90c7 = { c4 af [2] b0 b7 [2] f7 b5 [2] b0 a4 [2] fe a8 [2] f2 a2 [2] e5 a9 [2] fe e7 [2] c3 }

  condition:
    any of them
}