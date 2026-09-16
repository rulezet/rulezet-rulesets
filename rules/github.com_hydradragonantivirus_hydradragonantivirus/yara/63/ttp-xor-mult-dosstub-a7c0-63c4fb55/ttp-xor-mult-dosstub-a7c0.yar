rule TTP_XOR_MULT_DOSStub_a7c0 {
  strings:
    $key_a7c0 = { f3 a8 [2] 87 b0 [2] c0 b2 [2] 87 a3 [2] c9 af [2] c5 a5 [2] d2 ae [2] c9 e0 [2] f4 }

  condition:
    any of them
}