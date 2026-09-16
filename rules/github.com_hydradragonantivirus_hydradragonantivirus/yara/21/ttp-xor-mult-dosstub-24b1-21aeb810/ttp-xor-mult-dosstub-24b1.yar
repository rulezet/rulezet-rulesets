rule TTP_XOR_MULT_DOSStub_24b1 {
  strings:
    $key_24b1 = { 70 d9 [2] 04 c1 [2] 43 c3 [2] 04 d2 [2] 4a de [2] 46 d4 [2] 51 df [2] 4a 91 [2] 77 }

  condition:
    any of them
}