rule TTP_XOR_MULT_DOSStub_91c6 {
  strings:
    $key_91c6 = { c5 ae [2] b1 b6 [2] f6 b4 [2] b1 a5 [2] ff a9 [2] f3 a3 [2] e4 a8 [2] ff e6 [2] c2 }

  condition:
    any of them
}