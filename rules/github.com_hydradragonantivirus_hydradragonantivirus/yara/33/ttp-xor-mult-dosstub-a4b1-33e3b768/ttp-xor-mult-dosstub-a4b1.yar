rule TTP_XOR_MULT_DOSStub_a4b1 {
  strings:
    $key_a4b1 = { f0 d9 [2] 84 c1 [2] c3 c3 [2] 84 d2 [2] ca de [2] c6 d4 [2] d1 df [2] ca 91 [2] f7 }

  condition:
    any of them
}