rule TTP_XOR_MULT_DOSStub_a0b7 {
  strings:
    $key_a0b7 = { f4 df [2] 80 c7 [2] c7 c5 [2] 80 d4 [2] ce d8 [2] c2 d2 [2] d5 d9 [2] ce 97 [2] f3 }

  condition:
    any of them
}