rule TTP_XOR_MULT_DOSStub_a7c5 {
  strings:
    $key_a7c5 = { f3 ad [2] 87 b5 [2] c0 b7 [2] 87 a6 [2] c9 aa [2] c5 a0 [2] d2 ab [2] c9 e5 [2] f4 }

  condition:
    any of them
}