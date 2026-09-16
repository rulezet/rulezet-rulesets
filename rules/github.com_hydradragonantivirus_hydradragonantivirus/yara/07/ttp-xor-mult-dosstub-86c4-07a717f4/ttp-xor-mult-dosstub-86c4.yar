rule TTP_XOR_MULT_DOSStub_86c4 {
  strings:
    $key_86c4 = { d2 ac [2] a6 b4 [2] e1 b6 [2] a6 a7 [2] e8 ab [2] e4 a1 [2] f3 aa [2] e8 e4 [2] d5 }

  condition:
    any of them
}