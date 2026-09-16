rule TTP_XOR_MULT_DOSStub_d484 {
  strings:
    $key_d484 = { 80 ec [2] f4 f4 [2] b3 f6 [2] f4 e7 [2] ba eb [2] b6 e1 [2] a1 ea [2] ba a4 [2] 87 }

  condition:
    any of them
}