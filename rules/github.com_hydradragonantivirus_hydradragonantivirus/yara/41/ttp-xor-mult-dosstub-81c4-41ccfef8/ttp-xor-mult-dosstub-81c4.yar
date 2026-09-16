rule TTP_XOR_MULT_DOSStub_81c4 {
  strings:
    $key_81c4 = { d5 ac [2] a1 b4 [2] e6 b6 [2] a1 a7 [2] ef ab [2] e3 a1 [2] f4 aa [2] ef e4 [2] d2 }

  condition:
    any of them
}