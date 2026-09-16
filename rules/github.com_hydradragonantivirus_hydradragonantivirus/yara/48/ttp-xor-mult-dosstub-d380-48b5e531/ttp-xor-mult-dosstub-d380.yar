rule TTP_XOR_MULT_DOSStub_d380 {
  strings:
    $key_d380 = { 87 e8 [2] f3 f0 [2] b4 f2 [2] f3 e3 [2] bd ef [2] b1 e5 [2] a6 ee [2] bd a0 [2] 80 }

  condition:
    any of them
}