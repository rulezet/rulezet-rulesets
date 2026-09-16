rule TTP_XOR_MULT_DOSStub_a1b7 {
  strings:
    $key_a1b7 = { f5 df [2] 81 c7 [2] c6 c5 [2] 81 d4 [2] cf d8 [2] c3 d2 [2] d4 d9 [2] cf 97 [2] f2 }

  condition:
    any of them
}