rule TTP_XOR_MULT_DOSStub_d386 {
  strings:
    $key_d386 = { 87 ee [2] f3 f6 [2] b4 f4 [2] f3 e5 [2] bd e9 [2] b1 e3 [2] a6 e8 [2] bd a6 [2] 80 }

  condition:
    any of them
}