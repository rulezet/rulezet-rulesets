rule TTP_XOR_MULT_DOSStub_10b1 {
  strings:
    $key_10b1 = { 44 d9 [2] 30 c1 [2] 77 c3 [2] 30 d2 [2] 7e de [2] 72 d4 [2] 65 df [2] 7e 91 [2] 43 }

  condition:
    any of them
}