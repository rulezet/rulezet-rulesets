rule TTP_XOR_MULT_DOSStub_81c0 {
  strings:
    $key_81c0 = { d5 a8 [2] a1 b0 [2] e6 b2 [2] a1 a3 [2] ef af [2] e3 a5 [2] f4 ae [2] ef e0 [2] d2 }

  condition:
    any of them
}