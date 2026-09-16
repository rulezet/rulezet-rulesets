rule TTP_XOR_MULT_DOSStub_64b1 {
  strings:
    $key_64b1 = { 30 d9 [2] 44 c1 [2] 03 c3 [2] 44 d2 [2] 0a de [2] 06 d4 [2] 11 df [2] 0a 91 [2] 37 }

  condition:
    any of them
}