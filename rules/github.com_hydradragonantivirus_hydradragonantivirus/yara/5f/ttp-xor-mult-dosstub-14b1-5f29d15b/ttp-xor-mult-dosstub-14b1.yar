rule TTP_XOR_MULT_DOSStub_14b1 {
  strings:
    $key_14b1 = { 40 d9 [2] 34 c1 [2] 73 c3 [2] 34 d2 [2] 7a de [2] 76 d4 [2] 61 df [2] 7a 91 [2] 47 }

  condition:
    any of them
}