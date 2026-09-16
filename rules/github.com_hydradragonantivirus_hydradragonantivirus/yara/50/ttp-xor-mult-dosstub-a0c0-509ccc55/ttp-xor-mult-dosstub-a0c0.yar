rule TTP_XOR_MULT_DOSStub_a0c0 {
  strings:
    $key_a0c0 = { f4 a8 [2] 80 b0 [2] c7 b2 [2] 80 a3 [2] ce af [2] c2 a5 [2] d5 ae [2] ce e0 [2] f3 }

  condition:
    any of them
}