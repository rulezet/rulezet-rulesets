rule TTP_XOR_MULT_DOSStub_90c3 {
  strings:
    $key_90c3 = { c4 ab [2] b0 b3 [2] f7 b1 [2] b0 a0 [2] fe ac [2] f2 a6 [2] e5 ad [2] fe e3 [2] c3 }

  condition:
    any of them
}