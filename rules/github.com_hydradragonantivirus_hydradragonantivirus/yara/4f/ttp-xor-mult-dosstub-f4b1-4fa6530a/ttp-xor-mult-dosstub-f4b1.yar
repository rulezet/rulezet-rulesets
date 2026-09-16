rule TTP_XOR_MULT_DOSStub_f4b1 {
  strings:
    $key_f4b1 = { a0 d9 [2] d4 c1 [2] 93 c3 [2] d4 d2 [2] 9a de [2] 96 d4 [2] 81 df [2] 9a 91 [2] a7 }

  condition:
    any of them
}