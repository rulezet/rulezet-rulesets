rule TTP_XOR_MULT_DOSStub_90c5 {
  strings:
    $key_90c5 = { c4 ad [2] b0 b5 [2] f7 b7 [2] b0 a6 [2] fe aa [2] f2 a0 [2] e5 ab [2] fe e5 [2] c3 }

  condition:
    any of them
}