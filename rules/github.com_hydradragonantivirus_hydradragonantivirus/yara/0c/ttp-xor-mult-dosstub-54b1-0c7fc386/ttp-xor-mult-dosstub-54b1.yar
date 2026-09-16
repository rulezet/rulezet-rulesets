rule TTP_XOR_MULT_DOSStub_54b1 {
  strings:
    $key_54b1 = { 00 d9 [2] 74 c1 [2] 33 c3 [2] 74 d2 [2] 3a de [2] 36 d4 [2] 21 df [2] 3a 91 [2] 07 }

  condition:
    any of them
}