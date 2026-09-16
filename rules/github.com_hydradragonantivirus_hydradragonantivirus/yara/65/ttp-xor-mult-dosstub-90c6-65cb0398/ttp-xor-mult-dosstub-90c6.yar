rule TTP_XOR_MULT_DOSStub_90c6 {
  strings:
    $key_90c6 = { c4 ae [2] b0 b6 [2] f7 b4 [2] b0 a5 [2] fe a9 [2] f2 a3 [2] e5 a8 [2] fe e6 [2] c3 }

  condition:
    any of them
}