rule TTP_XOR_MULT_DOSStub_86c3 {
  strings:
    $key_86c3 = { d2 ab [2] a6 b3 [2] e1 b1 [2] a6 a0 [2] e8 ac [2] e4 a6 [2] f3 ad [2] e8 e3 [2] d5 }

  condition:
    any of them
}