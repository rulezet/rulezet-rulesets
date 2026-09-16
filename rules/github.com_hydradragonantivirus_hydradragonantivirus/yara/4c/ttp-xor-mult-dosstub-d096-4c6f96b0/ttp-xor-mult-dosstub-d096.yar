rule TTP_XOR_MULT_DOSStub_d096 {
  strings:
    $key_d096 = { 84 fe [2] f0 e6 [2] b7 e4 [2] f0 f5 [2] be f9 [2] b2 f3 [2] a5 f8 [2] be b6 [2] 83 }

  condition:
    any of them
}